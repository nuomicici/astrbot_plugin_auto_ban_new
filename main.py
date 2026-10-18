"""
AstrBot 进群禁言插件 v2.0

功能特性:
- 新成员入群自动禁言并发送欢迎引导消息
- 支持关键词解禁和戳一戳 Bot 快速解禁
- 递进式阶梯禁言机制
- 达到违规次数上限自动踢出
- 分群独立配置与 SQLite 数据库持久化存储
- 现代化 WebUI 可视化管理面板
"""
import asyncio
import random
import re
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star
import astrbot.api.message_components as Comp
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

from .database import AutoBanDatabase
from .web_controller import WebController


def generate_verification_challenge(config: Dict[str, Any]) -> Tuple[str, str]:
    """根据群配置的验证模式生成验证题目与期望答案。

    返回: (question_prompt, expected_answer)
    模式支持:
    - keyword: 指定关键词模式（不预设固定答案）
    - math_add_sub: 加减计算验证
    - math_mul_div: 乘除计算验证
    - custom_qa: 自定义问答 / 诗词填空
    """
    mode = str(config.get("verify_mode", "keyword")).strip().lower()

    if mode == "math_add_sub":
        # 10~99 范围内的整数加减法
        op = random.choice(["+", "-"])
        if op == "+":
            a = random.randint(10, 80)
            b = random.randint(5, 80)
            ans = a + b
            return f"{a} + {b} = ?", str(ans)
        else:
            a = random.randint(20, 99)
            b = random.randint(5, a - 5)
            ans = a - b
            return f"{a} - {b} = ?", str(ans)

    elif mode == "math_mul_div":
        # 乘法或可整除的除法
        op = random.choice(["*", "/"])
        if op == "*":
            a = random.randint(2, 12)
            b = random.randint(2, 9)
            ans = a * b
            return f"{a} × {b} = ?", str(ans)
        else:
            b = random.randint(2, 9)
            ans = random.randint(2, 12)
            a = b * ans
            return f"{a} ÷ {b} = ?", str(ans)

    elif mode == "custom_qa":
        # 自定义问答 / 诗词填空
        qa_text = str(config.get("custom_qa_list", "") or "").strip()
        pairs = []
        if qa_text:
            for line in qa_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                for sep in ["|", "｜", ":", "："]:
                    if sep in line:
                        q, a = line.split(sep, 1)
                        if q.strip() and a.strip():
                            pairs.append((q.strip(), a.strip()))
                        break

        if pairs:
            q, a = random.choice(pairs)
            return f"请回答：【{q}】", a
        else:
            return "请回答：【床前明月光】", "疑是地上霜"

    # keyword 模式直接通过关键词白名单判定
    return "", ""


def check_verification_answer(user_message: str, mode: str, expected_answer: str, config: Dict[str, Any]) -> bool:
    """根据验证模式校验用户发言是否满足解除监听条件"""
    mode = str(mode).strip().lower()
    user_text = user_message.strip()

    if mode in ("math_add_sub", "math_mul_div"):
        if not expected_answer:
            return True
        # 去除所有空格后严格匹配或正则单词边界匹配
        clean_text = user_text.replace(" ", "")
        if clean_text == expected_answer:
            return True
        pattern = rf"(?<!\d){re.escape(expected_answer)}(?!\d)"
        return bool(re.search(pattern, user_text))

    elif mode == "custom_qa":
        if not expected_answer:
            return True
        ans = expected_answer.strip().lower()
        return ans in user_text.lower()

    else:
        # keyword 模式校验白名单关键词
        whitelist_raw = config.get("whitelist_keywords", "我已阅读并同意遵守群规")
        keywords = [k.strip() for k in re.split(r"[,，\n]+", str(whitelist_raw)) if k.strip()]
        return any(kw.lower() in user_text.lower() for kw in keywords)


def format_template_message(
    template: str,
    user_id: str = "",
    question: str = "",
    count: int = 1,
    duration: int = 0,
    threshold: int = 7,
    append_question_fallback: bool = False
) -> str:
    """格式化消息模板，替换所有占位符并支持防重发随机内容。

    支持占位符:
    - {question} 或 {题目} 或 {验证题目}: 随机验证题目内容
    - {random} 或 {随机} 或 {随机内容}: 每次均不同的防重发随机字符
    - {user} 或 {用户} 或 {qq}: 成员 QQ 号
    - {count} 或 {次数} 或 {违规次数}: 当前违规次数
    - {duration} 或 {时长} 或 {禁言时长}: 禁言秒数
    - {threshold} 或 {阈值} 或 {踢出阈值}: 踢出上限阈值
    - {at} 或 {at_user} 或 {艾特}: 艾特该成员
    """
    if not template:
        return ""

    # 随机生成 4 位防重发字符串（避免平台因连续多条完全相同消息触发去重或风控拦截）
    random_code = "".join(random.choices("abcdefhkmnprstuvwxyz23456789", k=4))

    text = template

    replacements = {
        "{at}": f"[CQ:at,qq={user_id}]",
        "{at_user}": f"[CQ:at,qq={user_id}]",
        "{艾特}": f"[CQ:at,qq={user_id}]",
        "{question}": question,
        "{题目}": question,
        "{验证题目}": question,
        "{random}": random_code,
        "{随机}": random_code,
        "{随机内容}": random_code,
        "{user}": user_id,
        "{用户}": user_id,
        "{qq}": user_id,
        "{count}": str(count),
        "{次数}": str(count),
        "{违规次数}": str(count),
        "{duration}": str(duration),
        "{时长}": str(duration),
        "{禁言时长}": str(duration),
        "{threshold}": str(threshold),
        "{阈值}": str(threshold),
        "{踢出阈值}": str(threshold),
    }

    for placeholder, val in replacements.items():
        if placeholder in text:
            text = text.replace(placeholder, str(val))

    # 仅当显式指定 append_question_fallback=True（如入群欢迎或违规警告）且模版未显式填写题目占位符时才兜底追加
    if append_question_fallback and question and not any(k in template for k in ("{question}", "{题目}", "{验证题目}")):
        text += f"\n【验证题目】{question}（请回复正确答案以解除限制）"

    return text.strip()


class Main(Star):
    """进群禁言插件主类"""

    def __init__(self, context: Context):
        super().__init__(context)
        self.context = context
        self.config = context.get_config()

        # 初始化数据库路径
        db_dir = Path(get_astrbot_data_path()) / "plugin_data" / "astrbot_plugin_auto_ban_new"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = db_dir / "auto_ban.db"
        self.db = AutoBanDatabase(self.db_path)

        # 后台巡检任务状态
        self._periodic_check_task: Optional[asyncio.Task] = None
        self._is_running = False

        # 初始化 WebUI 控制器
        self.web_controller = WebController(context, self.db)

        logger.info("[AutoBan] 插件实例已创建")

    async def initialize(self):
        """插件生命周期：初始化"""
        await self.db.initialize()

        # 注册 WebUI 路由
        self.web_controller.register_routes()

        # 启动后台定期巡检任务
        self._is_running = True
        self._periodic_check_task = asyncio.create_task(self._periodic_member_check())

        logger.info("[AutoBan] 插件初始化完成，后台巡检任务已启动")

    async def terminate(self):
        """插件生命周期：终止与清理"""
        self._is_running = False

        if self._periodic_check_task and not self._periodic_check_task.done():
            self._periodic_check_task.cancel()
            try:
                await self._periodic_check_task
            except asyncio.CancelledError:
                pass

        logger.info("[AutoBan] 插件已终止，资源释放完毕")

    # ==================== 统一事件监听器 ====================

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.event_message_type(filter.EventMessageType.ALL, priority=100)
    async def handle_aiocqhttp_event(self, event: AstrMessageEvent):
        """统一监听来自 aiocqhttp (OneBot) 平台的事件"""
        raw = getattr(event.message_obj, "raw_message", None)
        if not isinstance(raw, dict):
            return

        post_type = raw.get("post_type")

        # 1. OneBot 通知事件（入群、退群、戳一戳）
        if post_type == "notice":
            notice_type = raw.get("notice_type")
            if notice_type == "group_increase":
                await self._handle_group_increase(event, raw)
            elif notice_type == "group_decrease":
                await self._handle_group_decrease(event, raw)
            elif notice_type == "notify" and raw.get("sub_type") == "poke":
                await self._handle_poke(event, raw)

        # 2. OneBot 消息事件（被监控群员消息拦截、白名单关键词匹配）
        elif post_type == "message":
            if raw.get("message_type") == "group":
                await self._handle_monitored_user_message(event, raw)

    # ==================== 业务处理逻辑 ====================

    async def _handle_group_increase(self, event: AstrMessageEvent, raw: dict):
        """处理新成员入群事件"""
        group_id = str(raw.get("group_id", "") or "").strip()
        user_id = str(raw.get("user_id", "") or "").strip()
        self_id = str(event.get_self_id() or "").strip()

        if not group_id or not user_id:
            return

        # 排除 Bot 自身入群
        if user_id == self_id:
            logger.info(f"[AutoBan] 机器人自身进入群 {group_id}，忽略入群事件")
            return

        # 检查群是否启用自动禁言
        config = await self.db.get_group_config(group_id)
        if not config or not config.get("enabled"):
            return

        logger.info(f"[AutoBan] 新成员 {user_id} 加入群 {group_id}")

        try:
            # 根据群配置的验证模式生成验证题目与期望答案
            verify_mode = str(config.get("verify_mode", "keyword")).strip().lower()
            verify_question, verify_answer = generate_verification_challenge(config)

            # 仅当开启后续监听时才加入监控列表（初始计数为 1，存储对应验证问题与期望答案）
            enable_monitoring = bool(config.get("enable_follow_up_monitoring", 0))
            if enable_monitoring:
                await self.db.add_monitored_user(
                    group_id=group_id,
                    user_id=user_id,
                    ban_count=1,
                    verify_question=verify_question,
                    verify_answer=verify_answer
                )

            # 首次禁言开关：仅当开启首次禁言开关且时长大于 0 时执行
            initial_duration = int(config.get("initial_ban_duration", 180))
            if bool(config.get("enable_initial_ban", 1)) and initial_duration > 0:
                await self._ban_user(event, group_id, user_id, initial_duration)
                logger.info(f"[AutoBan] 已对群 {group_id} 的新成员 {user_id} 执行首次入群禁言 {initial_duration} 秒")
            else:
                logger.info(f"[AutoBan] 群 {group_id} 首次禁言开关已关闭或时长为0，跳过对新成员 {user_id} 的入群禁言")

            # 发送欢迎及群规引导消息（通过占位符替换支持随机题目与防重发随机码）
            welcome_msg_template = config.get(
                "welcome_message",
                "欢迎加入本群！为了保证你能静下心看一眼群规，避免问出已有解决方法的问题，你已被自动禁言。请先查看群规并按照要求发送/执行动作，以取消禁言检测~"
            )
            formatted_welcome = format_template_message(
                template=welcome_msg_template,
                user_id=user_id,
                question=verify_question,
                count=1,
                duration=initial_duration,
                threshold=int(config.get("kick_threshold", 7)),
                append_question_fallback=True
            )

            if formatted_welcome and formatted_welcome.strip():
                await self._send_group_notice_message(event, group_id, user_id, formatted_welcome)
                logger.info(f"[AutoBan] 已向群 {group_id} 的新成员 {user_id} 发送欢迎引导消息 (模式: {verify_mode})")

        except Exception as e:
            logger.error(f"[AutoBan] 处理新成员入群事件出错: {e}")

    async def _handle_group_decrease(self, event: AstrMessageEvent, raw: dict):
        """处理群成员退出或被移出事件"""
        group_id = str(raw.get("group_id", "") or "").strip()
        user_id = str(raw.get("user_id", "") or "").strip()
        if not group_id or not user_id:
            return

        # 主动或被动退群后自动清理监控记录
        removed = await self.db.remove_monitored_user(group_id, user_id)
        if removed:
            logger.info(f"[AutoBan] 用户 {user_id} 离开群 {group_id}，已从监控列表中移除")

    async def _handle_poke(self, event: AstrMessageEvent, raw: dict):
        """处理戳一戳事件（快速解禁）"""
        group_id = str(raw.get("group_id", "") or "").strip()
        user_id = str(raw.get("user_id", "") or "").strip()
        target_id = str(raw.get("target_id", "") or "").strip()
        self_id = str(event.get_self_id() or "").strip()

        # 检查是否戳的是机器人自己
        if target_id != self_id:
            return

        # 检查群是否启用功能
        config = await self.db.get_group_config(group_id)
        if not config or not config.get("enabled"):
            return

        # 检查是否开启戳一戳解禁
        if not config.get("enable_poke_whitelist", 1):
            return

        # 检查用户是否在监控列表中
        user_info = await self.db.get_monitored_user(group_id, user_id)
        if not user_info:
            return

        try:
            # 解除禁言
            await self._unban_user(event, group_id, user_id)

            # 移出监控列表
            await self.db.remove_monitored_user(group_id, user_id)

            # 发送解禁提示（解禁成功，不附带题目）
            poke_template = config.get("poke_whitelist_message", "检测到戳一戳，已为您解除自动禁言监听~")
            formatted_poke = format_template_message(
                template=poke_template,
                user_id=user_id,
                question="",
                count=int(user_info.get("ban_count", 1)),
                duration=0,
                threshold=int(config.get("kick_threshold", 7)),
                append_question_fallback=False
            )
            if formatted_poke and formatted_poke.strip():
                await self._send_group_notice_message(event, group_id, user_id, formatted_poke)

            logger.info(f"[AutoBan] 用户 {user_id} 在群 {group_id} 通过戳一戳成功解除监听")
            event.stop_event()

        except Exception as e:
            logger.error(f"[AutoBan] 处理戳一戳解除监听时出错: {e}")

    async def _handle_monitored_user_message(self, event: AstrMessageEvent, raw: dict):
        """处理受监控用户的群聊消息（仅对处于监听状态的成员生效）"""
        group_id = str(event.get_group_id() or raw.get("group_id", "") or "").strip()
        user_id = str(event.get_sender_id() or raw.get("user_id", "") or "").strip()

        if not group_id or not user_id:
            return

        # 核心前置校验：查询该用户是否在数据库监控名单中
        # 若不在监控名单，说明是正常群成员或已完成验证，绝不拦截、不撤回、不影响其发言
        user_info = await self.db.get_monitored_user(group_id, user_id)
        if not user_info:
            return

        # 检查本群是否开启了进群禁言总开关
        config = await self.db.get_group_config(group_id)
        if not config or not config.get("enabled"):
            return

        # 检查是否启用了后续消息监听
        if not config.get("enable_follow_up_monitoring", 0):
            return

        # 获取消息纯文本
        message_text = event.message_str or ""
        if not message_text:
            components = event.get_messages()
            message_text = "".join(seg.text for seg in components if isinstance(seg, Comp.Plain))

        # 读取当前群配置的验证模式与分配给该用户的题目
        verify_mode = str(config.get("verify_mode", "keyword")).strip().lower()
        expected_answer = str(user_info.get("verify_answer", "") or "").strip()
        verify_question = str(user_info.get("verify_question", "") or "").strip()

        # 兜底：若该监控用户此前未生成题目，在此补全生成
        if not expected_answer and verify_mode != "keyword":
            verify_question, expected_answer = generate_verification_challenge(config)
            await self.db.add_monitored_user(
                group_id=group_id,
                user_id=user_id,
                ban_count=user_info.get("ban_count", 1),
                verify_question=verify_question,
                verify_answer=verify_answer
            )

        # 校验用户消息是否满足解禁条件
        is_passed = check_verification_answer(message_text, verify_mode, expected_answer, config)

        if is_passed:
            try:
                # 验证通过：解禁并移除监控，放行此消息，绝不撤回
                await self._unban_user(event, group_id, user_id)
                await self.db.remove_monitored_user(group_id, user_id)

                # 验证成功提示（不应再附带验证问题）
                success_template = config.get("whitelist_success_message", "检测到您已阅读群规，已取消监控，欢迎正常发言~")
                formatted_success = format_template_message(
                    template=success_template,
                    user_id=user_id,
                    question="",
                    count=int(user_info.get("ban_count", 1)),
                    duration=0,
                    threshold=int(config.get("kick_threshold", 7)),
                    append_question_fallback=False
                )
                if formatted_success and formatted_success.strip():
                    await self._send_group_notice_message(event, group_id, user_id, formatted_success)

                logger.info(f"[AutoBan] 监听中用户 {user_id} 在群 {group_id} 成功通过验证解除监听 (模式: {verify_mode})")
                event.stop_event()
                return
            except Exception as e:
                logger.error(f"[AutoBan] 解除监听处理出错: {e}")
                return

        # 未通过验证，属于监听中用户的违规发言
        try:
            # 1. 撤回开关：严格限制仅撤回当前处于监听中状态的用户所发送的违规消息
            if bool(config.get("enable_recall_noncompliant_messages", 0)):
                message_id = raw.get("message_id")
                if message_id is None and hasattr(event, "message_obj"):
                    message_id = getattr(event.message_obj, "message_id", None)

                # 校验发送者与监听中用户一致
                sender_id = str(raw.get("user_id") or event.get_sender_id() or "").strip()
                if message_id is not None and sender_id == user_id:
                    try:
                        await self._delete_msg(event, int(message_id))
                        logger.info(
                            f"[AutoBan] 已撤回监听中用户 {user_id} 在群 {group_id} 的未合规发言 (消息ID: {message_id})"
                        )
                    except Exception as e:
                        logger.warning(
                            f"[AutoBan] 撤回监听中用户 {user_id} 的违规消息失败 (可能机器人无管理权限或消息已撤回): {e}"
                        )

            # 2. 计次开关：若开启则统计违规次数并检查自动踢出阈值，关闭时不累加也不触发踢出
            current_count = int(user_info.get("ban_count", 1))
            if bool(config.get("enable_violation_count", 1)):
                new_count = current_count + 1
                await self.db.update_ban_count(group_id, user_id, new_count)
                kick_threshold = int(config.get("kick_threshold", 7))

                if new_count >= kick_threshold:
                    kick_template = config.get(
                        "kick_message",
                        '由于多次未按要求完成验证，你已被标记为恶意用户并移出群聊。'
                    )
                    formatted_kick = format_template_message(
                        template=kick_template,
                        user_id=user_id,
                        question=verify_question,
                        count=new_count,
                        duration=0,
                        threshold=kick_threshold,
                        append_question_fallback=False
                    )
                    if formatted_kick and formatted_kick.strip():
                        await self._send_group_notice_message(event, group_id, user_id, formatted_kick)

                    await self._kick_user(event, group_id, user_id)
                    await self.db.remove_monitored_user(group_id, user_id)
                    logger.info(f"[AutoBan] 用户 {user_id} 在群 {group_id} 违规达 {kick_threshold} 次，已执行踢出")
                    event.stop_event()
                    return
            else:
                new_count = current_count

            # 3. 后续禁言开关：若开启则执行递进禁言，关闭时跳过禁言操作
            if bool(config.get("enable_follow_up_ban", 1)):
                duration = self._get_ban_duration(config, new_count)
                await self._ban_user(event, group_id, user_id, duration)
                logger.info(f"[AutoBan] 用户 {user_id} 在群 {group_id} 第 {new_count} 次违规，执行禁言 {duration} 秒")
            else:
                duration = 0
                logger.info(f"[AutoBan] 群 {group_id} 后续禁言开关已关闭，跳过禁言处罚")

            # 4. 发送对应阶段违规提示（使用占位符替换，并在重复发送时提醒随机题目与防重发随机码）
            raw_ban_msg = self._get_ban_message(config, new_count)
            formatted_ban_msg = format_template_message(
                template=raw_ban_msg,
                user_id=user_id,
                question=verify_question,
                count=new_count,
                duration=duration,
                threshold=int(config.get("kick_threshold", 7)),
                append_question_fallback=True
            )

            if formatted_ban_msg and formatted_ban_msg.strip():
                await self._send_group_notice_message(event, group_id, user_id, formatted_ban_msg)

            logger.info(f"[AutoBan] 用户 {user_id} 在群 {group_id} 第 {new_count} 次违规，执行禁言 {duration} 秒")
            event.stop_event()

        except Exception as e:
            logger.error(f"[AutoBan] 处理监控用户违规发言出错: {e}")

    # ==================== 后台定期巡检 ====================

    async def _periodic_member_check(self):
        """定期检查被监控成员是否仍在群内，自动清理已离开的用户"""
        await asyncio.sleep(60)
        while self._is_running:
            try:
                all_users = await self.db.get_all_monitored_users()
                if all_users:
                    client = await self._get_any_client()
                    if client:
                        to_remove = []
                        for group_id, user_id, _ in all_users:
                            try:
                                result = await client.call_action(
                                    "get_group_member_info",
                                    group_id=int(group_id),
                                    user_id=int(user_id),
                                    no_cache=True
                                )
                                if not result:
                                    to_remove.append((group_id, user_id))
                            except Exception:
                                to_remove.append((group_id, user_id))

                        if to_remove:
                            count = await self.db.batch_remove_users(to_remove)
                            logger.info(f"[AutoBan] 定期巡检清理了 {count} 名已离开群聊的被监控用户")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[AutoBan] 定期巡检任务出错: {e}")

            # 每 10 分钟检查一次
            await asyncio.sleep(600)

    # ==================== OneBot API 封装 ====================

    async def _send_group_notice_message(self, event: AstrMessageEvent, group_id: str, user_id: str, formatted_text: str):
        """发送群提示消息，确保包含 @新成员，并具备 OneBot send_group_msg 兜底发信"""
        uid = int(user_id) if user_id.isdigit() else user_id
        has_cq_at = f"[CQ:at,qq={user_id}]" in formatted_text

        # 构建 AstrBot 消息链（若文本中未显式插入 [CQ:at]，则在消息开头自动加上 Comp.At 组件）
        if has_cq_at:
            chain = [Comp.Plain(formatted_text)]
        else:
            chain = [Comp.At(qq=uid), Comp.Plain(f" {formatted_text}")]

        sent = False
        try:
            await event.send(event.chain_result(chain))
            sent = True
        except Exception as e:
            logger.warning(f"[AutoBan] event.send 投递失败 (常见于 Notice 事件)，尝试使用 OneBot 原生 API 发信: {e}")

        # 若 event.send 投递失败（OneBot Notice 事件无会话上下文），通过 send_group_msg 兜底直发群聊
        if not sent:
            try:
                bot = getattr(event, "bot", None)
                msg_str = formatted_text if has_cq_at else f"[CQ:at,qq={user_id}] {formatted_text}"
                if bot and hasattr(bot, "call_action"):
                    await bot.call_action("send_group_msg", group_id=int(group_id), message=msg_str)
                elif bot and hasattr(bot, "api") and hasattr(bot.api, "call_action"):
                    await bot.api.call_action("send_group_msg", group_id=int(group_id), message=msg_str)
                else:
                    client = await self._get_any_client()
                    if client:
                        await client.call_action("send_group_msg", group_id=int(group_id), message=msg_str)
            except Exception as e:
                logger.error(f"[AutoBan] 兜底发送群消息失败: {e}")

    async def _ban_user(self, event: AstrMessageEvent, group_id: str, user_id: str, duration: int):
        """禁言用户"""
        bot = getattr(event, "bot", None)
        if bot and hasattr(bot, "set_group_ban"):
            await bot.set_group_ban(
                group_id=int(group_id),
                user_id=int(user_id),
                duration=int(duration)
            )
        else:
            client = await self._get_any_client()
            if client:
                await client.call_action(
                    "set_group_ban",
                    group_id=int(group_id),
                    user_id=int(user_id),
                    duration=int(duration)
                )

    async def _unban_user(self, event: AstrMessageEvent, group_id: str, user_id: str):
        """解除用户禁言"""
        await self._ban_user(event, group_id, user_id, 0)

    async def _delete_msg(self, event: AstrMessageEvent, message_id: int):
        """撤回消息"""
        bot = getattr(event, "bot", None)
        if bot and hasattr(bot, "delete_msg"):
            await bot.delete_msg(message_id=int(message_id))
        else:
            client = await self._get_any_client()
            if client:
                await client.call_action("delete_msg", message_id=int(message_id))

    async def _kick_user(self, event: AstrMessageEvent, group_id: str, user_id: str):
        """踢出群成员"""
        bot = getattr(event, "bot", None)
        if bot and hasattr(bot, "set_group_kick"):
            await bot.set_group_kick(
                group_id=int(group_id),
                user_id=int(user_id),
                reject_add_request=False
            )
        else:
            client = await self._get_any_client()
            if client:
                await client.call_action(
                    "set_group_kick",
                    group_id=int(group_id),
                    user_id=int(user_id),
                    reject_add_request=False
                )

    async def _get_any_client(self):
        """获取可用的 OneBot 客户端实例"""
        try:
            platform = self.context.get_platform(filter.PlatformAdapterType.AIOCQHTTP)
            if platform and hasattr(platform, "get_client"):
                return platform.get_client()
        except Exception:
            pass

        try:
            for inst in self.context.platform_manager.get_insts():
                if getattr(inst, "meta", lambda: None)().name == "aiocqhttp":
                    if hasattr(inst, "get_client"):
                        return inst.get_client()
                    if hasattr(inst, "client"):
                        return inst.client
        except Exception:
            pass
        return None

    def _get_ban_duration(self, config: Dict[str, Any], ban_count: int) -> int:
        """根据违规次数获取禁言时长"""
        if ban_count <= 2:
            return int(config.get("ban_duration_1", 180))
        elif ban_count == 3:
            return int(config.get("ban_duration_2", 180))
        elif ban_count == 4:
            return int(config.get("ban_duration_3", 600))
        else:
            return int(config.get("ban_duration_4", 3600))

    def _get_ban_message(self, config: Dict[str, Any], ban_count: int) -> str:
        """根据违规次数获取提示消息"""
        if ban_count <= 2:
            return config.get("ban_message_1", "第1次提醒：仍请先阅读群规，请先查看群规并按照要求发送/执行动作，以取消禁言检测~")
        elif ban_count == 3:
            return config.get("ban_message_2", "第2次提醒：多次未查看群规，禁言时间延长，请认真查看群规并按照要求发送/执行动作，以取消禁言检测~")
        elif ban_count == 4:
            return config.get("ban_message_3", "第3次提醒：请认真阅读群规后再发言，避免影响其他群员。")
        else:
            return config.get("ban_message_4", "还是不想查看吗？禁言时间已固定为最大时长，直至阅读群规并按照要求发送/执行动作，以取消禁言检测~")
