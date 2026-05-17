import asyncio
import json
import time
from collections.abc import AsyncGenerator
from functools import wraps
from pathlib import Path
from typing import Optional

import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import MessageEventResult, filter
from astrbot.api.star import Context, Star, register
from astrbot.core import AstrBotConfig
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
    AiocqhttpMessageEvent,
)
from astrbot.core.utils.astrbot_path import get_astrbot_data_path


# 权限组内容参考https://github.com/Zhalslar/astrbot_plugin_QQAdmin
class PermLevel:
    """权限级别枚举类"""

    UNKNOWN = -1
    MEMBER = 0
    HIGH = 1
    ADMIN = 2
    OWNER = 3
    SUPERUSER = 4

    @classmethod
    def from_str(cls, s: str) -> "PermLevel":
        s = s.lower()
        if s == "superuser":
            return cls.SUPERUSER
        elif s == "owner":
            return cls.OWNER
        elif s == "admin":
            return cls.ADMIN
        elif s == "high":
            return cls.HIGH
        elif s == "member":
            return cls.MEMBER
        else:
            return cls.UNKNOWN


class PermissionManager:
    """权限管理器单例类"""

    _instance: Optional["PermissionManager"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        superusers: list[str] | None = None,
        perms: dict[str, str] | None = None,
        level_threshold: int = 10,
    ):
        if self._initialized:
            return
        self.superusers = superusers or []
        self.perms: dict[str, PermLevel] = {
            k: PermLevel.from_str(v) for k, v in (perms or {}).items()
        }
        self.level_threshold = level_threshold
        self._initialized = True

    @classmethod
    def get_instance(
        cls,
        superusers: list[str] | None = None,
        perms: dict[str, str] | None = None,
        level_threshold: int = 50,
    ) -> "PermissionManager":
        if cls._instance is None:
            cls._instance = cls(
                superusers=superusers,
                perms=perms,
                level_threshold=level_threshold,
            )
        return cls._instance

    async def get_perm_level(
        self, event: AiocqhttpMessageEvent, user_id: str | int
    ) -> PermLevel:
        """获取用户在群内的权限级别"""
        group_id = event.get_group_id()
        if int(group_id) == 0 or int(user_id) == 0:
            return PermLevel.UNKNOWN
        if str(user_id) in self.superusers:
            return PermLevel.SUPERUSER
        try:
            info = await event.bot.get_group_member_info(
                group_id=int(group_id), user_id=int(user_id), no_cache=True
            )
        except Exception:
            return PermLevel.UNKNOWN
        role = info.get("role", "unknown")
        level = int(info.get("level", 0))

        if role == "owner":
            return PermLevel.OWNER
        elif role == "admin":
            return PermLevel.ADMIN
        elif role == "member":
            return PermLevel.HIGH if level >= self.level_threshold else PermLevel.MEMBER
        else:
            return PermLevel.UNKNOWN


# 权限检查装饰器
def perm_required(required_level: PermLevel, check_at: bool = True):
    """检查用户权限的装饰器"""

    def decorator(func):
        @wraps(func)
        async def wrapper(self, event: AiocqhttpMessageEvent, *args, **kwargs):
            # 非群聊环境直接拒绝
            if not event.get_group_id():
                yield event.plain_result("此命令仅在群聊中可用")
                return

            perm_mgr = PermissionManager.get_instance()
            user_level = await perm_mgr.get_perm_level(event, event.get_sender_id())

            # 检查用户权限
            if user_level < required_level:
                required_str = {
                    PermLevel.SUPERUSER: "超级管理员",
                    PermLevel.OWNER: "群主",
                    PermLevel.ADMIN: "管理员",
                    PermLevel.HIGH: "高等级成员",
                    PermLevel.MEMBER: "普通成员",
                }.get(required_level, "未知权限")
                yield event.plain_result(f"抱歉哦，需要{required_str}权限才可以设置~")
                return

            # 执行原函数
            async for result in func(self, event, *args, **kwargs):
                yield result

        return wrapper

    return decorator


# 高优先级常量，确保事件处理优先级
PRIO_HIGH = 100


def _high_priority(deco):
    """装饰器包装器，为事件处理器设置高优先级"""

    @wraps(deco)
    def wrapper(*args, **kwargs):
        kwargs.setdefault("priority", PRIO_HIGH)
        return deco(*args, **kwargs)

    return wrapper


# 高优先级事件装饰器
high_priority_event = _high_priority(filter.event_message_type)


def parse_switch_value(value: str) -> bool | None:
    """解析 on/off 类命令参数。"""
    normalized = value.strip().lower()
    if normalized in {"on", "true", "1", "yes", "y", "开启", "启用", "开"}:
        return True
    if normalized in {"off", "false", "0", "no", "n", "关闭", "禁用", "关"}:
        return False
    return None


@register(
    "astrbot_plugin_auto_ban_new",
    "糯米茨",
    "在指定群聊中对新入群用户自动禁言并发送欢迎消息，支持多种方式解除监听。",
    "v1.5",
)
class AutoBanNewMemberPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        self.config = config or {}

        # 初始化权限管理器
        self.admins_id = context.get_config().get("admins_id", [])
        self.perm_level_threshold = self.config.get("level_threshold", 50)
        self.permissions = self.config.get("permissions", {})

        PermissionManager.get_instance(
            superusers=self.admins_id,
            perms=self.permissions,
            level_threshold=self.perm_level_threshold,
        )

        # 读取基础配置
        self.target_groups = set(self.config.get("target_groups", []))

        # 新增：是否启用后续发言监测功能（默认关闭）
        self.enable_follow_up_monitoring = self.config.get(
            "enable_follow_up_monitoring", False
        )
        self.enable_recall_noncompliant_messages = self.config.get(
            "enable_recall_noncompliant_messages", False
        )

        # 构建禁言时长列表，提供默认值防止配置缺失
        ban_durations_config = self.config.get("ban_durations", {})
        self.ban_durations = [
            ban_durations_config.get("first_ban") or 180,
            ban_durations_config.get("second_ban") or 180,
            ban_durations_config.get("third_ban") or 600,
            ban_durations_config.get("fourth_and_more_ban") or 3600,
        ]

        # 读取消息配置，提供默认值
        self.welcome_message = self.config.get("welcome_message") or (
            "欢迎加入本群！为了保证你能静下心看一眼群规你已被自动禁言3分钟。"
            "\n请先查看群规，并阅读群公告。看完了还有问题可以@我"
        )

        ban_messages_config = self.config.get("ban_messages", {})
        self.ban_messages = [
            ban_messages_config.get("first_message")
            or "请先查看群规再发言，不要着急哦。",
            ban_messages_config.get("second_message")
            or "请先阅读群规和欢迎词内容，这次还是3分钟禁言~",
            ban_messages_config.get("third_message")
            or "多次未查看群规，禁言时间延长至10分钟，请认真阅读群规！",
            ban_messages_config.get("fourth_and_more_message")
            or "禁言时间固定为1小时，请认真阅读群规后再发言！",
        ]

        # 读取白名单关键词及提示配置
        self.whitelist_keywords = self.config.get("whitelist_keywords", [])
        self.whitelist_success_message = self.config.get("whitelist_success_message")
        if self.whitelist_success_message is None:
            self.whitelist_success_message = (
                "检测到您已阅读群规，已取消监控，欢迎正常发言~"
            )

        # 读取戳一戳功能配置
        self.enable_poke_whitelist = self.config.get("enable_poke_whitelist", True)
        self.poke_whitelist_message = (
            self.config.get("poke_whitelist_message")
            or "检测到戳一戳，已为您解除自动禁言监听~"
        )

        # 新增：踢出功能配置
        self.kick_threshold = self.config.get("kick_threshold", 7)
        self.kick_message = self.config.get("kick_message") or (
            '由于多次不看群规，你已被标记为"恶意用户"，现在踢出。你可以重新添加，但请记得查阅群规后再发言。'
        )

        # 用户禁言记录存储 (群ID, 用户ID): 累计禁言次数
        self.banned_users = {}

        # 使用框架标准方式获取数据目录
        self.data_dir = (
            Path(get_astrbot_data_path())
            / "plugin_data"
            / "astrbot_plugin_auto_ban_new"
        )
        self.data_file = self.data_dir / "banned_users.json"

        # 检查并迁移旧数据目录的数据（如果存在）
        self._migrate_old_data()

        # 后台任务状态标记，防止重复启动定时任务
        self._periodic_task_started = False

    async def initialize(self):
        """插件初始化"""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self._load_banned_users()
            # 只有启用后续监测时才启动定期检查任务
            if self.enable_follow_up_monitoring:
                asyncio.create_task(self.periodic_member_check())
                self._periodic_task_started = True
                logger.info(
                    "自动禁言新成员插件已初始化，后续发言监测功能已启用，成功加载历史数据并启动后台检查任务"
                )
            else:
                logger.info(
                    "自动禁言新成员插件已初始化，后续发言监测功能已关闭，仅对新成员进行入群禁言"
                )
        except PermissionError as e:
            logger.error(f"初始化插件时权限不足: {e}")
        except OSError as e:
            logger.error(f"初始化插件时文件系统错误: {e}")
        except Exception as e:
            logger.error(f"初始化插件时出现未预期的错误: {e}")

    async def terminate(self):
        """插件终止时保存数据"""
        try:
            if self.enable_follow_up_monitoring:
                self._save_banned_users()
                logger.info("自动禁言新成员插件已终止，成功保存数据")
            else:
                logger.info("自动禁言新成员插件已终止")
        except PermissionError as e:
            logger.error(f"终止插件时权限不足，无法保存数据: {e}")
        except OSError as e:
            logger.error(f"终止插件时文件系统错误: {e}")
        except Exception as e:
            logger.error(f"终止插件时出现未预期的错误: {e}")

    def _migrate_old_data(self):
        """检查并迁移旧数据目录的数据文件"""
        try:
            import shutil

            from astrbot.core.star.star_tools import StarTools

            old_data_dir = StarTools.get_data_dir("astrbot_plugin_auto_ban_new")
            old_data_file = old_data_dir / "banned_users.json"

            # 如果旧数据文件存在且新数据文件不存在，则迁移数据
            if old_data_file.exists() and not self.data_file.exists():
                self.data_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(old_data_file, self.data_file)
                logger.info(f"已将旧数据文件从 {old_data_file} 迁移到 {self.data_file}")
        except ImportError:
            # StarTools 不存在，跳过迁移
            logger.debug("StarTools 不可用，跳过旧数据迁移")
        except Exception as e:
            logger.warning(f"迁移旧数据时出错: {e}")

    def _load_banned_users(self):
        """从文件加载被禁言用户数据"""
        # 如果未启用后续监测，则不需要加载历史数据
        if not self.enable_follow_up_monitoring:
            self.banned_users = {}
            return

        try:
            if self.data_file.exists():
                with open(self.data_file, encoding="utf-8") as f:
                    data = json.load(f)
                self.banned_users = {}
                for item in data:
                    if not isinstance(item, list) or len(item) != 2:
                        continue
                    key_list, count = item
                    if not isinstance(key_list, list) or len(key_list) != 2:
                        continue
                    group_id, user_id = key_list
                    try:
                        group_id = str(group_id)
                        user_id = int(user_id)
                    except (TypeError, ValueError):
                        continue
                    self.banned_users[(group_id, user_id)] = count
                logger.debug(
                    f"从{self.data_file}加载了{len(self.banned_users)}个被禁言用户"
                )
            else:
                self.banned_users = {}
        except Exception as e:
            logger.error(f"加载被禁言用户数据失败: {e}")
            self.banned_users = {}

    def _save_banned_users(self):
        """将被禁言用户数据保存到文件"""
        # 如果未启用后续监测，则不需要保存数据
        if not self.enable_follow_up_monitoring:
            return

        try:
            data = []
            for key, value in self.banned_users.items():
                group_id, user_id = key
                data.append([[str(group_id), int(user_id)], value])
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(
                f"已将{len(self.banned_users)}个被禁言用户保存到{self.data_file}"
            )
        except Exception as e:
            logger.error(f"保存被禁言用户数据失败: {e}")

    def check_target_group(self, group_id: str) -> bool:
        """检查是否为目标群聊"""
        return group_id in self.target_groups

    def is_valid_message(self, event: AiocqhttpMessageEvent) -> bool:
        """判断消息是否为有效消息，排除戳一戳等特殊消息"""
        try:
            message_components = event.get_messages()
            message_outline = event.get_message_outline()
            if "[poke]" in message_outline:
                return False
            if message_components:
                return any(not isinstance(seg, Comp.Poke) for seg in message_components)

            raw_message = getattr(event.message_obj, "raw_message", None)
            raw_segments = (
                raw_message.get("message") if isinstance(raw_message, dict) else None
            )
            if isinstance(raw_segments, list):
                return any(
                    seg.get("type") != "poke"
                    for seg in raw_segments
                    if isinstance(seg, dict)
                )
            return False
        except Exception as e:
            logger.error(f"判断消息有效性时出错: {e}")
            return True

    async def recall_noncompliant_message(
        self, event: AiocqhttpMessageEvent, group_id: str, user_id: int
    ) -> None:
        """按配置撤回被监听用户未按要求发送的消息。"""
        if not self.enable_recall_noncompliant_messages:
            return

        message_id = getattr(event.message_obj, "message_id", None)
        if message_id in (None, ""):
            logger.warning(
                f"用户 {user_id} 在群 {group_id} 的违规发言缺少 message_id，无法撤回。"
            )
            return

        try:
            await event.bot.delete_msg(message_id=int(message_id))
            logger.info(
                f"已撤回用户 {user_id} 在群 {group_id} 中未按要求发送的消息 {message_id}。"
            )
        except (TypeError, ValueError):
            logger.warning(
                f"用户 {user_id} 在群 {group_id} 的违规发言 message_id 非数字，无法撤回: {message_id!r}"
            )
        except Exception as e:
            logger.warning(
                f"撤回用户 {user_id} 在群 {group_id} 中未按要求发送的消息 {message_id} 失败: {e}"
            )

    async def get_mute_remaining_seconds(
        self, event: AiocqhttpMessageEvent, group_id: str, user_id: int
    ) -> int | None:
        """获取群成员当前剩余禁言时间，查询失败时返回 None。"""
        try:
            member_info = await event.bot.get_group_member_info(
                group_id=int(group_id), user_id=int(user_id), no_cache=True
            )
        except Exception as e:
            logger.warning(
                f"查询用户 {user_id} 在群 {group_id} 的禁言状态失败，将继续按本插件规则处理: {e}"
            )
            return None

        try:
            shut_up_timestamp = int(member_info.get("shut_up_timestamp") or 0)
        except (TypeError, ValueError):
            logger.warning(
                f"用户 {user_id} 在群 {group_id} 的禁言状态字段异常: {member_info.get('shut_up_timestamp')!r}"
            )
            return None

        if shut_up_timestamp <= 0:
            return 0
        return max(0, shut_up_timestamp - int(time.time()))

    def remove_user_from_watchlist(self, user_identifier: tuple, reason: str) -> bool:
        """从监听列表中移除用户"""
        group_id, user_id = user_identifier
        if user_identifier in self.banned_users:
            del self.banned_users[user_identifier]
            self._save_banned_users()
            logger.info(f'用户 {user_id} 在群 {group_id} 中因"{reason}"被解除监听')
            return True
        return False

    @high_priority_event(filter.EventMessageType.ALL)
    async def handle_group_increase(self, event: AiocqhttpMessageEvent):
        """处理新成员入群事件"""
        try:
            if not hasattr(event, "message_obj") or not hasattr(
                event.message_obj, "raw_message"
            ):
                return
            raw_message = event.message_obj.raw_message
            if not raw_message or not isinstance(raw_message, dict):
                return

            # 检查是否为群成员增加通知
            if (
                raw_message.get("post_type") == "notice"
                and raw_message.get("notice_type") == "group_increase"
            ):
                group_id = str(raw_message.get("group_id", ""))
                user_id = int(raw_message.get("user_id", 0))

                # 非目标群直接返回
                if not self.check_target_group(group_id):
                    return

                try:
                    # 新成员入群：执行第1次禁言
                    user_identifier = (group_id, user_id)
                    first_ban_duration = self.ban_durations[0]
                    await event.bot.set_group_ban(
                        group_id=int(group_id),
                        user_id=user_id,
                        duration=first_ban_duration,
                    )
                    logger.info(
                        f"已在群{group_id}中第1次禁言新成员{user_id}，时长{first_ban_duration}秒"
                    )

                    # 只有启用后续监测时才记录用户到监听列表
                    if self.enable_follow_up_monitoring:
                        self.banned_users[user_identifier] = 1
                        self._save_banned_users()
                        logger.debug(
                            f"已添加用户到监听列表：{user_identifier}，累计禁言次数：1"
                        )
                    else:
                        logger.debug(
                            f"后续发言监测功能已关闭，不将用户{user_id}添加到监听列表"
                        )

                    # 发送欢迎消息
                    chain = [Comp.At(qq=user_id), Comp.Plain(text=self.welcome_message)]
                    yield event.chain_result(chain)

                except Exception as e:
                    logger.error(f"处理新成员入群事件出错: {e}")
        except Exception as e:
            logger.error(f"handle_group_increase 方法出错: {e}")

    @high_priority_event(filter.EventMessageType.ALL)
    async def handle_group_decrease(self, event: AiocqhttpMessageEvent):
        """处理群成员减少事件（主动退群或被踢）"""
        # 如果未启用后续监测，则不需要处理成员减少事件
        if not self.enable_follow_up_monitoring:
            return

        try:
            if not hasattr(event, "message_obj") or not hasattr(
                event.message_obj, "raw_message"
            ):
                return
            raw_message = event.message_obj.raw_message
            if not isinstance(raw_message, dict):
                return

            # 检查是否为群成员减少通知
            if (
                raw_message.get("post_type") == "notice"
                and raw_message.get("notice_type") == "group_decrease"
            ):
                group_id = str(raw_message.get("group_id", ""))
                user_id = int(raw_message.get("user_id", 0))

                # 非目标群直接返回
                if not self.check_target_group(group_id):
                    return

                user_identifier = (group_id, user_id)
                # 如果用户在监听列表中，则移除
                self.remove_user_from_watchlist(
                    user_identifier, reason="成员离开或被移出群聊"
                )

        except Exception as e:
            logger.error(f"handle_group_decrease 方法出错: {e}")

    @high_priority_event(filter.EventMessageType.ALL)
    async def handle_poke_whitelist(self, event: AiocqhttpMessageEvent):
        """处理戳一戳解除监听事件"""
        # 如果未启用后续监测或未启用戳一戳白名单，则直接返回
        if not self.enable_follow_up_monitoring or not self.enable_poke_whitelist:
            return

        try:
            # 检查是否为戳一戳消息
            message_components = event.get_messages()
            if not message_components or not isinstance(
                message_components[0], Comp.Poke
            ):
                return

            raw_message = getattr(event.message_obj, "raw_message", None)
            if not raw_message:
                return

            target_id = raw_message.get("target_id", 0)
            user_id = raw_message.get("user_id", 0)
            group_id = str(raw_message.get("group_id", ""))
            self_id = raw_message.get("self_id", 0)

            # 检查是否戳的是机器人自己
            if target_id != self_id:
                return

            # 检查是否为目标群
            if not self.check_target_group(group_id):
                return

            user_identifier = (group_id, user_id)

            # 检查用户是否在监听列表中
            if user_identifier not in self.banned_users:
                return

            # 从监听列表中移除用户
            if self.remove_user_from_watchlist(user_identifier, "戳一戳"):
                # 发送解除监听提示消息
                chain = [
                    Comp.At(qq=user_id),
                    Comp.Plain(text=self.poke_whitelist_message),
                ]
                yield event.chain_result(chain)

        except Exception as e:
            logger.error(f"处理戳一戳解除监听事件出错: {e}")

    @high_priority_event(filter.EventMessageType.GROUP_MESSAGE)
    async def handle_banned_user_message(self, event: AiocqhttpMessageEvent):
        """处理被监听用户的群消息"""
        # 如果未启用后续监测，则直接返回，不处理任何消息
        if not self.enable_follow_up_monitoring:
            return

        try:
            if not hasattr(event, "message_obj") or not hasattr(
                event.message_obj, "raw_message"
            ):
                return
            raw_message = event.message_obj.raw_message
            if not raw_message or not isinstance(raw_message, dict):
                return

            group_id = str(raw_message.get("group_id", ""))
            user_id = int(raw_message.get("user_id", 0))
            user_identifier = (group_id, user_id)

            # 非目标群不处理
            if not self.check_target_group(group_id):
                return

            # 不在监听列表中的用户不处理
            if user_identifier not in self.banned_users:
                return

            # 检查消息中是否包含解除监听关键词
            message_chain = event.get_messages()
            message_text = "".join(
                [seg.text for seg in message_chain if isinstance(seg, Comp.Plain)]
            ).lower()

            # 检查是否包含任何白名单关键词
            has_whitelist_keyword = any(
                keyword.lower() in message_text for keyword in self.whitelist_keywords
            )

            # 包含白名单关键词则移除监听
            if has_whitelist_keyword:
                removed = self.remove_user_from_watchlist(user_identifier, "关键词")
                if removed and self.whitelist_success_message.strip():
                    await event.send(event.plain_result(self.whitelist_success_message))
                event.stop_event()
                return

            # 无效消息不触发禁言
            if not self.is_valid_message(event):
                logger.debug(f"用户{user_id}发送了无效消息，不触发禁言")
                return

            await self.recall_noncompliant_message(event, group_id, user_id)

            # 有效消息且无白名单关键词则触发禁言或踢出
            try:
                current_total_count = self.banned_users[user_identifier]
                duration_index = min(current_total_count, len(self.ban_durations) - 1)
                current_ban_duration = self.ban_durations[duration_index]
                mute_remaining = await self.get_mute_remaining_seconds(
                    event, group_id, user_id
                )

                if mute_remaining is not None and mute_remaining > current_ban_duration:
                    logger.info(
                        f"跳过用户 {user_id} 在群 {group_id} 的后续禁言：当前剩余禁言 {mute_remaining} 秒，"
                        f"超过本插件本次计划禁言 {current_ban_duration} 秒，可能已被其他禁言插件或群管操作占用。"
                    )
                    event.stop_event()
                    return

                if mute_remaining is not None and mute_remaining > 0:
                    logger.info(
                        f"用户 {user_id} 在群 {group_id} 当前仍处于禁言中，剩余 {mute_remaining} 秒未超过"
                        f"本插件本次计划禁言 {current_ban_duration} 秒，将刷新覆盖。"
                    )

                new_total_count = current_total_count + 1

                # 检查是否达到踢出阈值
                if new_total_count >= self.kick_threshold:
                    kick_message_chain = [
                        Comp.At(qq=user_id),
                        Comp.Plain(text=self.kick_message),
                    ]
                    await event.send(event.chain_result(kick_message_chain))

                    await event.bot.set_group_kick(
                        group_id=int(group_id),
                        user_id=user_id,
                        reject_add_request=False,
                    )
                    logger.info(
                        f"用户 {user_id} 在群 {group_id} 中因达到 {self.kick_threshold} 次禁言上限被踢出。"
                    )

                    # 从监听列表移除用户
                    self.remove_user_from_watchlist(user_identifier, "达到踢出阈值")
                    event.stop_event()
                    return  # 结束处理

                # 如果未达到踢出阈值，则执行禁言
                await event.bot.set_group_ban(
                    group_id=int(group_id),
                    user_id=user_id,
                    duration=current_ban_duration,
                )
                logger.info(
                    f"已第{new_total_count}次禁言用户{user_id}，时长{current_ban_duration}秒"
                )

                # 更新禁言次数
                self.banned_users[user_identifier] = new_total_count
                self._save_banned_users()

                # 发送对应的提示消息
                message_index = min(current_total_count, len(self.ban_messages) - 1)
                reminder_message = self.ban_messages[message_index]

                response_chain = [
                    Comp.At(qq=user_id),
                    Comp.Plain(text=reminder_message),
                ]
                await event.send(event.chain_result(response_chain))
                event.stop_event()

            except Exception as e:
                logger.error(f"处理被禁言用户消息时执行禁言或踢出操作出错: {e}")
        except Exception as e:
            logger.error(f"handle_banned_user_message 方法出错: {e}")

    async def periodic_member_check(self):
        """定期检查被监听的用户是否还在群内，以防错过退群事件"""
        # 如果未启用后续监测，则不启动定期检查任务
        if not self.enable_follow_up_monitoring:
            return

        await asyncio.sleep(60)  # 启动后稍作等待，避免与其他启动任务冲突
        while True:
            try:
                # 获取 aiocqhttp 平台实例
                client = next(
                    (
                        c
                        for p in self.context.platform_manager.get_insts()
                        if p.meta().name == "aiocqhttp" and (c := p.get_client())
                    ),
                    None,
                )

                if not client:
                    logger.warning(
                        "未能获取到 aiocqhttp 平台实例，成员检查将在1小时后重试。"
                    )
                    await asyncio.sleep(3600)
                    continue
                # 按群组ID对被监听用户进行分组，以减少API调用次数
                groups_to_check = {}
                # 创建banned_users的副本进行迭代，防止在迭代过程中修改字典
                for group_id, user_id in list(self.banned_users.keys()):
                    if group_id not in groups_to_check:
                        groups_to_check[group_id] = set()
                    groups_to_check[group_id].add(user_id)

                if groups_to_check:
                    logger.debug(
                        f"开始定期成员检查，涉及 {len(groups_to_check)} 个群聊。"
                    )

                for group_id, users_in_group_to_check in groups_to_check.items():
                    try:
                        # 获取群成员列表
                        members_info = await client.call_action(
                            "get_group_member_list",
                            group_id=int(group_id),
                            no_cache=True,
                        )
                        current_member_ids = {
                            member["user_id"] for member in members_info
                        }

                        # 找出已经不在群里的用户
                        users_left = users_in_group_to_check - current_member_ids

                        for user_id in users_left:
                            user_identifier = (group_id, user_id)
                            self.remove_user_from_watchlist(
                                user_identifier, "定期检查发现用户已不在群内"
                            )

                        # 避免API调用过于频繁
                        await asyncio.sleep(5)

                    except Exception as e:
                        logger.error(f"定期检查群 {group_id} 成员时出错: {e}")

            except Exception as e:
                logger.error(f"periodic_member_check 任务发生未知错误: {e}")

            # 每小时检查一次
            await asyncio.sleep(3600)

    @filter.command("添加启用群聊")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def add_target_group(
        self, event: AiocqhttpMessageEvent, group_id: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """添加启用群聊"""
        # 验证群号格式（必须为纯数字）
        if not group_id.isdigit():
            yield event.plain_result("群号必须为纯数字")
            return

        # 检查是否已经在列表中
        if group_id in self.target_groups:
            yield event.plain_result(f"群 {group_id} 已在启用列表中")
            return

        # 添加到配置
        self.target_groups.add(group_id)
        target_groups_list = list(self.target_groups)
        self.config["target_groups"] = target_groups_list
        self.config.save_config()

        yield event.plain_result(f"已添加群 {group_id} 到启用列表")

    # 命令功能
    @filter.command_group("自动禁言")
    def auto_ban_commands(self):
        """自动禁言插件命令组"""
        pass

    @auto_ban_commands.command("off")
    @perm_required(PermLevel.ADMIN)
    async def disable_monitoring(
        self, event: AiocqhttpMessageEvent
    ) -> AsyncGenerator[MessageEventResult, None]:
        """关闭后续禁言监测功能"""
        self.enable_follow_up_monitoring = False
        self.config["enable_follow_up_monitoring"] = False
        self.config.save_config()
        yield event.plain_result(
            "已关闭后续发言监测功能，新成员入群仍会被禁言，但不会进行后续监听"
        )

    @auto_ban_commands.command("on")
    @perm_required(PermLevel.ADMIN)
    async def enable_monitoring(
        self, event: AiocqhttpMessageEvent
    ) -> AsyncGenerator[MessageEventResult, None]:
        """开启后续禁言监测功能"""
        self.enable_follow_up_monitoring = True
        self.config["enable_follow_up_monitoring"] = True
        self.config.save_config()

        # 启动后台检查任务（如果尚未启动）
        if not self._periodic_task_started:
            asyncio.create_task(self.periodic_member_check())
            self._periodic_task_started = True

        yield event.plain_result("已开启后续发言监测功能，新成员入群后将被持续监听")

    @auto_ban_commands.command("撤回")
    @perm_required(PermLevel.ADMIN)
    async def set_recall_noncompliant_messages(
        self, event: AiocqhttpMessageEvent, switch: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置是否撤回被监听用户未按要求发送的消息"""
        enabled = parse_switch_value(switch)
        if enabled is None:
            yield event.plain_result("参数应为 on/off、开启/关闭 或 true/false")
            return

        self.enable_recall_noncompliant_messages = enabled
        self.config["enable_recall_noncompliant_messages"] = enabled
        self.config.save_config()

        status = "开启" if enabled else "关闭"
        yield event.plain_result(f"已{status}未按要求发言自动撤回功能")

    @auto_ban_commands.command("名单")
    @filter.permission_type(filter.PermissionType.ADMIN)
    async def show_ban_list(
        self, event: AiocqhttpMessageEvent
    ) -> AsyncGenerator[MessageEventResult, None]:
        """查看当前被监听的用户名单（仅超级管理员）"""
        if not self.banned_users:
            yield event.plain_result("当前没有被监听的用户")
            return

        # 构建表格
        lines = ["===当前禁言监听名单===", "群号        | 昵称           | QQ号"]
        lines.append("-" * 45)

        for (group_id, user_id), ban_count in self.banned_users.items():
            # 尝试获取用户昵称
            nickname = str(user_id)
            try:
                member_info = await event.bot.get_group_member_info(
                    group_id=int(group_id), user_id=int(user_id), no_cache=False
                )
                nickname = (
                    member_info.get("nickname")
                    or member_info.get("card")
                    or str(user_id)
                )
                # 截断过长的昵称
                if len(nickname) > 10:
                    nickname = nickname[:9] + "…"
            except Exception:
                nickname = "(未知)"

            # 格式化输出行
            lines.append(
                f"{group_id:<11} | {nickname:<14} | {user_id} (禁言{ban_count}次)"
            )

        lines.append("-" * 45)
        lines.append(f"共 {len(self.banned_users)} 人")

        yield event.plain_result("\n".join(lines))

    @filter.command("设置解禁关键词")
    @perm_required(PermLevel.ADMIN)
    async def set_whitelist_keywords(
        self, event: AiocqhttpMessageEvent, keywords: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置解除监听的关键词"""
        # 解析关键词（用空格分隔）
        keyword_list = [kw.strip() for kw in keywords.split() if kw.strip()]
        if not keyword_list:
            yield event.plain_result("请提供至少一个关键词，用空格分隔")
            return

        self.whitelist_keywords = keyword_list
        self.config["whitelist_keywords"] = keyword_list
        self.config.save_config()

        keywords_str = "、".join(keyword_list)
        yield event.plain_result(f"已设置解禁关键词：{keywords_str}")

    @filter.command("设置禁言踢出次数")
    @perm_required(PermLevel.ADMIN)
    async def set_kick_threshold(
        self, event: AiocqhttpMessageEvent, threshold: int
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置踢出阈值"""
        # 验证阈值范围
        if threshold < 2:
            yield event.plain_result("踢出阈值不能小于2次")
            return
        if threshold > 50:
            yield event.plain_result("踢出阈值不能大于50次")
            return

        self.kick_threshold = threshold
        self.config["kick_threshold"] = threshold
        self.config.save_config()
        yield event.plain_result(f"已设置踢出阈值为：{threshold} 次")

    @filter.command("设置解禁提示消息")
    @perm_required(PermLevel.ADMIN)
    async def set_whitelist_success_message(
        self, event: AiocqhttpMessageEvent, message: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置解禁提示消息"""
        self.whitelist_success_message = message
        self.config["whitelist_success_message"] = message
        self.config.save_config()
        if message.strip():
            yield event.plain_result(f"已设置解禁提示消息：\n{message}")
        else:
            yield event.plain_result(
                "已设置解禁提示消息为空，触发关键词解禁时将不再发送提示文本"
            )

    @filter.command("设置禁言时长")
    @perm_required(PermLevel.ADMIN)
    async def set_ban_durations(
        self, event: AiocqhttpMessageEvent, durations_str: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置禁言时长"""
        try:
            # 解析参数，格式：1/300 2/600 3/1800 4/3600
            duration_pairs = durations_str.strip().split()
            new_durations = [180, 180, 600, 3600]  # 默认值

            for pair in duration_pairs:
                if "/" not in pair:
                    yield event.plain_result(f"格式错误：{pair}，应为 次数/时长 格式")
                    return

                try:
                    count_str, duration_str = pair.split("/", 1)
                    count = int(count_str)
                    duration = int(duration_str)

                    # 验证参数
                    if count < 1 or count > 4:
                        yield event.plain_result(
                            f"禁言次数应在1-4之间，但收到：{count}"
                        )
                        return
                    if duration < 10 or duration > 86400:  # 10秒到24小时
                        yield event.plain_result(
                            f"禁言时长应在10-86400秒之间，但收到：{duration}"
                        )
                        return

                    # 设置时长（索引从0开始）
                    new_durations[count - 1] = duration

                except ValueError:
                    yield event.plain_result(f"格式错误：{pair}，次数和时长必须为整数")
                    return

            # 更新配置
            self.ban_durations = new_durations
            ban_durations_config = {
                "first_ban": new_durations[0],
                "second_ban": new_durations[1],
                "third_ban": new_durations[2],
                "fourth_and_more_ban": new_durations[3],
            }
            self.config["ban_durations"] = ban_durations_config
            self.config.save_config()

            duration_info = f"第1次：{new_durations[0]}秒，第2次：{new_durations[1]}秒，第3次：{new_durations[2]}秒，第4次及以后：{new_durations[3]}秒"
            yield event.plain_result(f"已设置禁言时长：\n{duration_info}")

        except Exception as e:
            logger.error(f"设置禁言时长时出错: {e}")
            yield event.plain_result(
                "设置失败，请检查参数格式。示例：1/10 2/100 3/1000 4/10000"
            )

    @filter.command("设置入群提醒")
    @perm_required(PermLevel.ADMIN)
    async def set_welcome_message(
        self, event: AiocqhttpMessageEvent, message: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置新成员入群欢迎消息"""
        if not message.strip():
            yield event.plain_result("欢迎消息不能为空")
            return

        self.welcome_message = message
        self.config["welcome_message"] = message
        self.config.save_config()
        yield event.plain_result(f"已设置入群提醒：\n{message}")

    @filter.command("设置禁言提示消息")
    @perm_required(PermLevel.ADMIN)
    async def set_ban_message(
        self, event: AiocqhttpMessageEvent, config_str: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置禁言提示消息"""
        try:
            # 解析参数，格式：次数/消息内容
            if "/" not in config_str:
                yield event.plain_result("格式错误，应为：次数/消息内容")
                return

            count_str, message = config_str.split("/", 1)
            count = int(count_str)

            # 验证次数范围
            if count < 1 or count > 4:
                yield event.plain_result("禁言次数应在1-4之间")
                return

            if not message.strip():
                yield event.plain_result("提示消息不能为空")
                return

            # 更新对应的提示消息
            ban_messages_config = self.config.get("ban_messages", {})
            message_keys = [
                "first_message",
                "second_message",
                "third_message",
                "fourth_and_more_message",
            ]

            ban_messages_config[message_keys[count - 1]] = message
            self.config["ban_messages"] = ban_messages_config

            # 更新内存中的配置
            self.ban_messages[count - 1] = message

            self.config.save_config()
            yield event.plain_result(f"已设置第{count}次禁言提示消息：\n{message}")

        except ValueError:
            yield event.plain_result("次数必须为整数，格式：次数/消息内容")
        except Exception as e:
            logger.error(f"设置禁言提示消息时出错: {e}")
            yield event.plain_result("设置失败，请检查参数格式")

    @filter.command("设置戳一戳提示消息")
    @perm_required(PermLevel.ADMIN)
    async def set_poke_message(
        self, event: AiocqhttpMessageEvent, message: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置戳一戳解除监听提示消息"""
        self.poke_whitelist_message = message
        self.config["poke_whitelist_message"] = message
        self.config.save_config()

        if message.strip():
            yield event.plain_result(f"已设置戳一戳解除监听提示消息：\n{message}")
        else:
            yield event.plain_result("已设置戳一戳解除监听提示消息为空（不发送提示）")

    @filter.command("设置踢出提示消息")
    @perm_required(PermLevel.ADMIN)
    async def set_kick_message(
        self, event: AiocqhttpMessageEvent, message: str
    ) -> AsyncGenerator[MessageEventResult, None]:
        """设置踢出提示消息"""
        if not message.strip():
            yield event.plain_result("踢出提示消息不能为空")
            return

        self.kick_message = message
        self.config["kick_message"] = message
        self.config.save_config()
        yield event.plain_result(f"已设置踢出提示消息：\n{message}")

    @filter.command("进群禁言帮助", alias={"自动禁言帮助"})
    async def show_help(
        self, event: AiocqhttpMessageEvent
    ) -> AsyncGenerator[MessageEventResult, None]:
        """显示插件帮助信息"""
        help_text = """===AstrBot 自动禁言插件===
v1.5 by 糯米茨(3218444911)
插件简介：
在指定群聊中对新入群用户自动禁言并发送欢迎消息，支持多种方式解除监听。帮助群管理员更好地管理新成员，确保新成员先阅读群规再发言。
可用命令（仅群管理员&BOT管理员）：
⚙️ 功能设置
- /自动禁言 off/on - 关闭/开启后续禁言监测
- /自动禁言 撤回 on/off - 设置是否撤回未按要求的发言
- /设置解禁关键词 <关键词> - 设置解除监听关键词
- /设置禁言踢出次数 <次数> - 设置踢出阈值
- /设置禁言时长 <配置> - 设置各次禁言时长

✅ 信息提示
- /设置入群提醒 <消息内容> - 设置入群提示消息
- /设置禁言提示消息 <次数/消息> - 设置禁言提示消息
- /设置戳一戳提示消息 <消息内容> - 设置戳一戳解除提示
- /设置解禁提示消息 <消息内容> - 设置关键词解除后的提示文本
- /设置踢出提示消息 <消息内容> - 设置踢出提示消息
- /进群禁言帮助 - 显示此帮助信息

🛠️ 超级管理员专用
- /添加启用群聊 <群号> - 添加启用群聊
- /自动禁言 名单 - 查看当前被监听的用户名单

示例用法：
- /设置解禁关键词 我已阅读群规 同意遵守
- /设置禁言踢出次数 5
- /设置禁言时长 1/60 2/300 3/1800 4/7200
- /自动禁言 撤回 on
- /添加启用群聊 123456789
- /设置入群提醒 欢迎新成员！请先阅读群规
- /设置禁言提示消息 2/请仔细阅读群规后再发言
- /设置戳一戳提示消息 已为您解除监听
- /设置踢出提示消息 多次违规，现在移除群聊
解除监听方式：
1. 发送包含解禁关键词的消息
2. 戳一戳机器人（需开启此功能）
3. 主动退群或被踢出群聊

⚠注意！提示消息无法识别空格和换行，请使用标点符号分隔！"""

        yield event.plain_result(help_text)
