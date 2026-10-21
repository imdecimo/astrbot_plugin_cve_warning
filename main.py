import asyncio

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star

from .core.cve_warning_service import CVEWarningService, RefreshResult
from .core.log_utils import sanitize

BACKOFF_SECONDS = (30, 60, 300)

# 服务连续稳定运行超过这个时长后，下一次崩溃的退避从 30s 重新算起。
STABLE_RUN_SECONDS = 300

DISABLED_NOTICE = (
    "ℹ️ 插件已在配置中禁用（enabled=false），定时任务不会启动；"
    "如需推送请先在 WebUI 打开 enabled。"
)

REFRESH_STATUS_LABELS = {
    "unchanged": "目录版本未变，无新增",
    "seeded": "已建立基线，本轮不推送",
    "no_targets": "未配置推送会话，仅更新基线",
}

REFRESH_ERROR_LABELS = {
    "service_not_ready": "服务尚未就绪（可能仍在启动或重启），请稍后重试",
}


class CVEWarningPlugin(Star):
    """CVE 漏洞（CISA KEV）增量推送插件"""

    def __init__(self, context: Context, config: AstrBotConfig) -> None:
        super().__init__(context)
        self.context = context
        self.config: AstrBotConfig = config
        self.service: CVEWarningService | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        self._stopping = False

    # ------------------------------------------------------------ 生命周期

    async def initialize(self) -> None:
        if not self.config.get("enabled", True):
            logger.info("[CVE漏洞推送] 插件已禁用，跳过初始化")
            return
        logger.info("[CVE漏洞推送] 正在初始化...")
        self._stopping = False
        self._supervisor_task = asyncio.create_task(
            self._supervisor(), name="cve_warning_supervisor"
        )

    async def _supervisor(self) -> None:
        """跑服务直到收到停止指令，中途崩溃按 30s → 60s → 300s 退避重启。"""
        loop = asyncio.get_running_loop()
        failures = 0
        while not self._stopping:
            delay = 0
            started_at = loop.time()
            try:
                # 构造也必须在 try 里：配置被手改成非数字时 __init__ 的 int() 会抛
                # ValueError，写在外面会让 supervisor 协程静默结束、永不重启。
                self.service = CVEWarningService(
                    config=dict(self.config), context=self.context
                )
                await self.service.start()
                if not self._stopping:
                    # start() 只在收到停止或前置条件不满足时正常返回；没收到停止指令
                    # 就退出属于异常，同样退避，否则 while 会紧凑空转刷日志。
                    failures, delay = self._schedule_restart(
                        failures, loop.time() - started_at
                    )
                    logger.warning(
                        f"[CVE漏洞推送] 服务在未收到停止指令的情况下退出，"
                        f"{delay}s 后重启（第 {failures} 次）"
                    )
            except asyncio.CancelledError:
                self._stopping = True
                break
            except Exception as e:
                failures, delay = self._schedule_restart(
                    failures, loop.time() - started_at
                )
                logger.error(
                    f"[CVE漏洞推送] 服务异常退出，{delay}s 后重启（第 {failures} 次）: "
                    f"{sanitize(e)}"
                )
            finally:
                await self._stop_service()
            if delay and not self._stopping:
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    self._stopping = True
                    break

    @staticmethod
    def _backoff_seconds(failures: int) -> int:
        return BACKOFF_SECONDS[min(failures, len(BACKOFF_SECONDS) - 1)]

    @classmethod
    def _schedule_restart(cls, failures: int, elapsed: float) -> tuple[int, int]:
        """给出本次重启的等待秒数，以及更新后的连续失败计数。

        重置策略：服务若已连续稳定运行超过 STABLE_RUN_SECONDS，先把失败计数清零，
        再按第 1 次失败算退避。否则跑了几天的服务偶然崩一次，第一轮就要白等 300s。
        崩溃（elapsed 很小）时计数照常累加，30s → 60s → 300s 封顶。
        """
        if elapsed >= STABLE_RUN_SECONDS and failures:
            logger.info(
                f"[CVE漏洞推送] 服务已稳定运行 {int(elapsed)}s，重启退避计数清零"
            )
            failures = 0
        return failures + 1, cls._backoff_seconds(failures)

    async def _stop_service(self) -> None:
        service = self.service
        if service is None:
            return
        try:
            await service.stop()
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 停止服务时出错: {sanitize(e)}")
        # stop() 走完（或被取消）之后再清引用：await 被取消时保留引用，
        # terminate() 末尾的第二次 _stop_service() 才能真的把 session 收掉。
        if self.service is service:
            self.service = None

    async def terminate(self) -> None:
        logger.info("[CVE漏洞推送] 正在停止服务...")
        self._stopping = True
        task = self._supervisor_task
        self._supervisor_task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 等待后台任务退出时出错: {sanitize(e)}")
        await self._stop_service()

    # ---------------------------------------------------------------- 命令

    async def is_plugin_admin(self, event: AstrMessageEvent) -> bool:
        if event.is_admin():
            return True
        sender_id = event.get_sender_id()
        sender_id_str = str(sender_id).strip() if sender_id is not None else ""
        raw_admins = self.config.get("admin_users", []) or []
        if not isinstance(raw_admins, list):
            return False
        return sender_id_str in [str(item).strip() for item in raw_admins if str(item).strip()]

    @filter.command("CVE漏洞推送")
    async def cve_help(self, event: AstrMessageEvent):
        help_text = """🛡️ CVE漏洞推送（CISA KEV）使用说明

📋 可用命令：
• /CVE漏洞推送 - 显示本帮助
• /CVE漏洞推送状态 - 查看运行状态（管理员）
• /CVE漏洞推送手动刷新 - 立即拉取并推送新增（管理员）

⚙️ 重要说明：
• 首次启动只建立基线，不推送任何历史漏洞；之后只推真正新加入 KEV 的条目
• 目录版本未变时不再逐条解析条目、不查 NVD（服务端支持 ETag 时连响应体都不下载）
• 推送会话在 WebUI 的 target_sessions 里填，格式 平台:消息类型:会话ID，
  在目标群发 /sid 指令可获取
• 一轮新增会合并成一条消息；中文摘要依赖 AstrBot 已配置的聊天模型，
  未配置时退回英文原文
• 发送判定口径是「适配器是否报错」，协议端返回成功但被平台拦截的情况无法检测"""
        yield event.plain_result(help_text)

    @filter.command("CVE漏洞推送状态")
    async def cve_status(self, event: AstrMessageEvent):
        if not await self.is_plugin_admin(event):
            yield event.plain_result("🚫 权限不足：此命令仅限管理员使用。")
            return
        if not self.config.get("enabled", True):
            yield event.plain_result(DISABLED_NOTICE)
            return
        if not self.service:
            yield event.plain_result("❌ 服务未启动（或正在重启）")
            return

        try:
            status = self.service.get_status()
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 获取状态失败: {sanitize(e)}")
            yield event.plain_result(f"❌ 获取状态失败: {sanitize(e)}")
            return

        yield event.plain_result(self._format_status(status))

    @filter.command("CVE漏洞推送手动刷新")
    async def cve_manual_refresh(self, event: AstrMessageEvent):
        if not await self.is_plugin_admin(event):
            yield event.plain_result("🚫 权限不足：此命令仅限管理员使用。")
            return
        if not self.config.get("enabled", True):
            yield event.plain_result(DISABLED_NOTICE)
            return
        if not self.service:
            yield event.plain_result("❌ 服务未启动（或正在重启）")
            return

        try:
            result = await self.service.refresh_and_push(reason="manual")
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 手动刷新失败: {sanitize(e)}")
            yield event.plain_result(f"❌ 手动刷新失败: {sanitize(e)}")
            return

        if not result.ok:
            error_text = REFRESH_ERROR_LABELS.get(result.error or "", result.error)
            yield event.plain_result(f"❌ 手动刷新失败：{error_text}")
            return

        yield event.plain_result(self._format_refresh_result(result))

    # ------------------------------------------------------------ 文案组装

    def _format_status(self, status: dict) -> str:
        pending = status.get("pending")
        if not isinstance(pending, dict):
            pending = {}
        pending_text = (
            "、".join(f"{session}(attempts={attempts})" for session, attempts in pending.items())
            if pending
            else "无"
        )
        persistent = status.get("persistent")
        ai_outcome = status.get("ai_last_outcome")
        # 展示服务实际生效的间隔（服务会把配置值 clamp 到 1–48），不展示配置原值。
        interval_hours = getattr(self.service, "interval_hours", None)
        interval_text = f"{interval_hours} 小时" if isinstance(interval_hours, int) else "未知"
        lines = [
            "📊 CVE漏洞推送状态",
            f"🟢 running: {status.get('running')}",
            f"💾 状态落盘: {'是' if persistent else '否（状态目录不可写，本次运行仅内存态）'}",
            f"🧾 catalog_version: {status.get('catalog_version')}",
            f"📚 基线条数: {status.get('baseline_count')}",
            f"⏰ 上次拉取: {status.get('last_fetch_at_iso')}",
            f"📣 上次推送: {status.get('last_push_at_iso')}",
            f"⏭️ 下次运行: {status.get('next_run_at')}",
            f"🕒 拉取间隔: {interval_text}",
            f"📮 待补发会话与尝试次数: {pending_text}",
            f"⚠️ 上轮适配器报错会话数: {status.get('last_failed_sessions')}",
            f"🗑️ 累计放弃补发次数（按会话×轮次计）: {status.get('abandoned_total')}",
            f"🤖 AI 摘要: {'开启' if status.get('ai_summary_enabled') else '关闭'}"
            f"（上次结果: {ai_outcome}）",
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_refresh_result(result: RefreshResult) -> str:
        if result.status == "catalog_anomaly":
            # 该状态下 result.ok 仍为 True，但本轮什么都没推出去、版本也没写回，
            # 所以不能按成功展示，也不能把抓到的版本说成"当前目录版本"。
            return (
                "⚠️ 手动刷新完成，但 KEV 目录解析异常：本轮未推送，下一轮会自动重试\n"
                f"本轮抓到的目录版本: {result.catalog_version}"
                f"（解析异常，未写入状态，状态中仍是上一轮版本）\n"
                "新增: 未判定（本轮未与基线比对）\n"
                f"适配器报错会话数: {result.failed_sessions}\n"
                f"放弃补发次数: {result.abandoned}"
            )

        if result.status == "pushed":
            if result.failed_sessions > 0:
                # 有会话没发出去时不能写"已推送"：用户会以为全都送达了。
                if result.new_count > 0:
                    headline = (
                        f"⚠️ 手动刷新完成：本轮新增 {result.new_count} 条"
                        f"（其中 {result.failed_sessions} 个会话适配器报错，将进入补发队列）"
                    )
                else:
                    headline = (
                        f"⚠️ 手动刷新完成：本轮无新增，且 {result.failed_sessions} 个会话适配器"
                        f"补发时仍然报错，内容继续留在待补发队列，下一轮重试"
                    )
            elif result.new_count > 0:
                headline = f"✅ 手动刷新完成：已推送新增 {result.new_count} 条"
            else:
                headline = "✅ 手动刷新完成：本轮无新增，只补发了此前未送达的内容"
        else:
            label = REFRESH_STATUS_LABELS.get(result.status, result.status)
            headline = f"✅ 手动刷新完成：{label}"

        # 304 与"仅补发"轮次不会设置 catalog_version，别把 None 抛给用户。
        version_text = result.catalog_version or "未变（沿用上一轮）"
        return (
            f"{headline}\n"
            f"目录版本: {version_text}\n"
            f"新增: {result.new_count} 条\n"
            f"适配器报错会话数: {result.failed_sessions}\n"
            f"放弃补发次数: {result.abandoned}"
        )
