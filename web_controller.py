"""
WebUI 后端 API 控制器
对接 AstrBot WebUI 视图系统与 OneBot 接口
"""
import asyncio
import time
from typing import Dict, List, Any, Optional

from astrbot.api import logger
from astrbot.api.event import filter
from astrbot.api.star import Context
from astrbot.api.web import error_response, json_response, request

from .database import AutoBanDatabase

PLUGIN_NAME = "astrbot_plugin_auto_ban_new"


class WebController:
    """WebUI API 控制器"""

    def __init__(self, context: Context, db: AutoBanDatabase):
        self.context = context
        self.db = db
        self._group_cache: List[Dict[str, Any]] = []
        self._cache_lock = asyncio.Lock()
        self._cache_time = 0
        self._cache_ttl = 90  # 缓存 90 秒

    def register_routes(self):
        """注册 Web API 路由"""
        routes = [
            (f"/{PLUGIN_NAME}/api/ping", self.ping, ["GET"], "健康检查"),
            (f"/{PLUGIN_NAME}/api/groups", self.get_groups, ["GET"], "获取群聊列表"),
            (f"/{PLUGIN_NAME}/api/groups/refresh", self.refresh_groups, ["POST"], "刷新群聊列表"),
            (f"/{PLUGIN_NAME}/api/group/<group_id>/config", self.handle_group_config, ["GET", "POST"], "群配置管理"),
            (f"/{PLUGIN_NAME}/api/group/<group_id>/monitored_users", self.get_monitored_users, ["GET"], "获取监控用户列表"),
            (f"/{PLUGIN_NAME}/api/group/<group_id>/monitored_users/<user_id>", self.remove_monitored_user, ["POST", "DELETE"], "移除监控用户"),
            (f"/{PLUGIN_NAME}/api/group/<group_id>/monitored_users/<user_id>/remove", self.remove_monitored_user, ["POST", "DELETE"], "移除监控用户"),
        ]

        for path, handler, methods, desc in routes:
            self.context.register_web_api(
                path,
                self._wrap_handler(handler),
                methods,
                desc,
            )

        logger.info(f"[AutoBan] Web API 路由注册完成，共 {len(routes)} 个端点")

    def _wrap_handler(self, handler):
        """统一错误处理包装器"""
        async def wrapped(*args, **kwargs):
            try:
                return await handler(*args, **kwargs)
            except ValueError as e:
                return error_response(str(e))
            except Exception as e:
                logger.exception("[AutoBan] Web API 执行异常")
                return error_response(f"服务器内部错误: {e}")
        return wrapped

    async def ping(self):
        """健康检查"""
        return json_response({"ok": True, "message": "pong"})

    async def get_groups(self):
        """获取群列表（带 90 秒 TTL 缓存）"""
        async with self._cache_lock:
            now = time.time()
            if self._group_cache and (now - self._cache_time) < self._cache_ttl:
                return json_response({"ok": True, "data": self._group_cache})

        groups = await self._fetch_groups()

        async with self._cache_lock:
            self._group_cache = groups
            self._cache_time = time.time()

        return json_response({"ok": True, "data": groups})

    async def refresh_groups(self):
        """强制刷新群列表缓存"""
        groups = await self._fetch_groups()

        async with self._cache_lock:
            self._group_cache = groups
            self._cache_time = time.time()

        return json_response({"ok": True, "data": groups})

    async def _fetch_groups(self) -> List[Dict[str, Any]]:
        """从 OneBot 客户端与数据库获取并聚合群列表，仅保留 Bot 为管理员或群主的群聊"""
        group_map = {}

        try:
            client = await self._get_any_client()
            if client:
                try:
                    # 先预先获取一次 Bot 自身的 QQ 号，避免在遍历群列表时重复调用
                    bot_id = await self._get_bot_id(client)

                    result = await client.call_action("get_group_list")
                    group_list = result if isinstance(result, list) else result.get("data", [])
                    if isinstance(group_list, list):
                        for item in group_list:
                            group_id = str(item.get("group_id", "")).strip()
                            if not group_id:
                                continue

                            bot_role = await self._get_bot_role(client, group_id, bot_id=bot_id)
                            # 仅保留 Bot 具有管理员(admin)或群主(owner)权限的群聊
                            if bot_role not in ("admin", "owner"):
                                continue

                            group_map[group_id] = {
                                "group_id": group_id,
                                "group_name": str(item.get("group_name", "")).strip() or f"群 {group_id}",
                                "avatar": f"https://p.qlogo.cn/gh/{group_id}/{group_id}/640",
                                "member_count": int(item.get("member_count", 0)),
                                "bot_role": bot_role,
                            }
                except Exception as e:
                    logger.warning(f"[AutoBan] 从 OneBot 获取群列表失败: {e}")
        except Exception as e:
            logger.error(f"[AutoBan] 连接 OneBot 客户端失败: {e}")

        # 检查数据库中已配置的群，若 Bot 依然具备管理权限则补全展示
        try:
            db_groups = await self.db.list_enabled_groups()
            client = await self._get_any_client()
            if client:
                bot_id = await self._get_bot_id(client)
                for group_id in db_groups:
                    if group_id not in group_map:
                        bot_role = await self._get_bot_role(client, group_id, bot_id=bot_id)
                        if bot_role in ("admin", "owner"):
                            group_map[group_id] = {
                                "group_id": group_id,
                                "group_name": f"群 {group_id}",
                                "avatar": f"https://p.qlogo.cn/gh/{group_id}/{group_id}/640",
                                "member_count": 0,
                                "bot_role": bot_role,
                            }
        except Exception as e:
            logger.warning(f"[AutoBan] 补全数据库群列表失败: {e}")

        groups = list(group_map.values())

        # 排序：群主(owner) > 管理员(admin)，群号从小到大
        role_priority = {"owner": 0, "admin": 1}
        groups.sort(key=lambda g: (
            role_priority.get(g.get("bot_role", "admin"), 1),
            int(g["group_id"]) if g["group_id"].isdigit() else 9999999999
        ))

        return groups

    async def _get_bot_id(self, client) -> Optional[int]:
        """获取 Bot 自身的 QQ 号"""
        try:
            login_info = await client.call_action("get_login_info")
            if isinstance(login_info, dict):
                uid = login_info.get("user_id") or login_info.get("data", {}).get("user_id")
                return int(uid) if uid else None
        except Exception:
            pass
        return None

    async def _get_bot_role(self, client, group_id: str, bot_id: Optional[int] = None) -> str:
        """获取 Bot 在指定群内的身份角色"""
        try:
            if not bot_id:
                bot_id = await self._get_bot_id(client)

            if not bot_id:
                return "unknown"

            result = await client.call_action(
                "get_group_member_info",
                group_id=int(group_id),
                user_id=int(bot_id),
                no_cache=True
            )

            info = result if isinstance(result, dict) else result.get("data", {})
            return str(info.get("role", "member")).lower()

        except Exception:
            return "unknown"

    async def handle_group_config(self, group_id: str):
        """单群配置读取与保存"""
        group_id = str(group_id).strip()

        if request.method == "GET":
            config = await self.db.get_group_config(group_id)
            if not config:
                config = self._get_default_config()
                config["group_id"] = group_id
            return json_response({"ok": True, "data": config})

        elif request.method == "POST":
            payload = await request.json(default={})
            if not isinstance(payload, dict):
                return error_response("请求数据必须是有效 JSON 字典")

            await self.db.upsert_group_config(group_id, payload)
            config = await self.db.get_group_config(group_id)
            return json_response({"ok": True, "message": "群配置保存成功", "data": config})

        return error_response("不支持的请求方法")

    async def get_monitored_users(self, group_id: str):
        """获取指定群的当前监控用户列表"""
        group_id = str(group_id).strip()
        users = await self.db.get_group_monitored_users(group_id)
        enriched_users = []
        client = await self._get_any_client()

        for user in users:
            uid = str(user["user_id"])
            nickname = f"用户 {uid}"
            if client:
                try:
                    result = await client.call_action(
                        "get_group_member_info",
                        group_id=int(group_id),
                        user_id=int(uid),
                        no_cache=True
                    )
                    info = result if isinstance(result, dict) else result.get("data", {})
                    card = info.get("card", "")
                    raw_nick = info.get("nickname", "")
                    nickname = card or raw_nick or nickname
                except Exception:
                    pass

            enriched_users.append({
                "user_id": uid,
                "ban_count": user["ban_count"],
                "nickname": nickname,
                "avatar": f"https://q1.qlogo.cn/g?b=qq&nk={uid}&s=640",
                "created_at": user.get("created_at", ""),
                "updated_at": user.get("updated_at", ""),
            })

        return json_response({"ok": True, "data": enriched_users})

    async def remove_monitored_user(self, group_id: str, user_id: str):
        """手动解除对指定用户的监控"""
        group_id = str(group_id).strip()
        user_id = str(user_id).strip()

        success = await self.db.remove_monitored_user(group_id, user_id)
        if not success:
            return error_response(f"在群 {group_id} 中未找到用户 {user_id} 的监控记录")

        return json_response({"ok": True, "message": f"已成功移除对用户 {user_id} 的监控"})

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

    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        """获取默认配置字典（全部群聊默认关闭监听）"""
        return {
            "enabled": 0,  # 群总功能开关（默认关闭）
            "enable_initial_ban": 1,  # 首次禁言开关（默认开启）
            "enable_follow_up_monitoring": 0,  # 后续监听开关（默认关闭）
            "enable_follow_up_ban": 1,  # 后续禁言开关（默认开启）
            "enable_recall_noncompliant_messages": 0,  # 撤回开关（默认关闭）
            "enable_violation_count": 1,  # 计次开关（默认开启）
            "enable_poke_whitelist": 1,
            "initial_ban_duration": 180,
            "kick_threshold": 7,
            "ban_duration_1": 180,
            "ban_duration_2": 180,
            "ban_duration_3": 600,
            "ban_duration_4": 3600,
            "verify_mode": "keyword",  # 验证模式: keyword(指定关键词), math_add_sub(加减计算), math_mul_div(乘除计算), custom_qa(自定义问答/填空)
            "whitelist_keywords": "我已阅读并同意遵守群规",
            "custom_qa_list": "床前明月光|疑是地上霜\n天王盖地虎|宝塔镇河妖\n春眠不觉晓|处处闻啼鸟",
            "welcome_message": "欢迎加入本群！为了保证你能静下心看一眼群规，避免问出已有解决方法的问题，你已被自动禁言。\n【验证题目】{question}\n请在群内回复正确答案以取消禁言限制~",
            "whitelist_success_message": "检测到您已阅读群规并正确回答，已取消监控，欢迎正常发言~",
            "poke_whitelist_message": "检测到戳一戳，已为您解除自动禁言监听~",
            "kick_message": '由于多次未按要求完成验证，你已被标记为恶意用户并移出群聊。',
            "ban_message_1": "第1次提醒：仍请先阅读群规，当前验证题目为：{question}，请在群内回复正确答案以解除限制~",
            "ban_message_2": "第2次提醒：答案错误或未按要求作答，禁言时间已延长至{duration}秒。请认真查看题目并回复：{question}",
            "ban_message_3": "第3次提醒：请认真阅读群规后再发言，当前题目：{question}。达到{threshold}次违规将被移出群聊。",
            "ban_message_4": "第{count}次违规：禁言时间已固定为最大时长，请回复正确答案解除限制：{question}"
        }
