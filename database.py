"""
数据库管理模块 - 使用 SQLite 存储群配置和监控数据
"""
import asyncio
import aiosqlite
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from astrbot.api import logger


class AutoBanDatabase:
    """进群禁言插件数据库"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """初始化数据库表结构"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                # 创建分群配置表（全部群聊默认关闭监听 enabled = 0）
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS group_config (
                        group_id TEXT PRIMARY KEY,
                        enabled INTEGER DEFAULT 0,
                        enable_initial_ban INTEGER DEFAULT 1,
                        enable_follow_up_monitoring INTEGER DEFAULT 0,
                        enable_follow_up_ban INTEGER DEFAULT 1,
                        enable_recall_noncompliant_messages INTEGER DEFAULT 0,
                        enable_violation_count INTEGER DEFAULT 1,
                        enable_poke_whitelist INTEGER DEFAULT 1,
                        kick_threshold INTEGER DEFAULT 7,
                        ban_duration_1 INTEGER DEFAULT 180,
                        ban_duration_2 INTEGER DEFAULT 180,
                        ban_duration_3 INTEGER DEFAULT 600,
                        ban_duration_4 INTEGER DEFAULT 3600,
                        whitelist_keywords TEXT DEFAULT '我已阅读并同意遵守群规',
                        verify_mode TEXT DEFAULT 'keyword',
                        custom_qa_list TEXT DEFAULT '',
                        welcome_message TEXT DEFAULT '欢迎加入本群！为了保证你能静下心看一眼群规，避免问出已有解决方法的问题，你已被自动禁言。\n【验证题目】{question}\n请在群内回复正确答案以取消禁言限制~',
                        whitelist_success_message TEXT DEFAULT '检测到您已阅读群规并正确回答，已取消监控，欢迎正常发言~',
                        poke_whitelist_message TEXT DEFAULT '检测到戳一戳，已为您解除自动禁言监听~',
                        kick_message TEXT DEFAULT '由于多次未按要求完成验证，你已被标记为恶意用户并移出群聊。',
                        ban_message_1 TEXT DEFAULT '第1次提醒：仍请先阅读群规，当前验证题目为：{question}，请在群内回复正确答案以解除限制~',
                        ban_message_2 TEXT DEFAULT '第2次提醒：答案错误或未按要求作答，禁言时间已延长至{duration}秒。请认真查看题目并回复：{question}',
                        ban_message_3 TEXT DEFAULT '第3次提醒：请认真阅读群规后再发言，当前题目：{question}。达到{threshold}次违规将被移出群聊。',
                        ban_message_4 TEXT DEFAULT '第{count}次违规：禁言时间已固定为最大时长，请回复正确答案解除限制：{question}',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # 创建监控用户表
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS monitored_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        ban_count INTEGER DEFAULT 0,
                        verify_question TEXT DEFAULT '',
                        verify_answer TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(group_id, user_id)
                    )
                """)
                
                # 创建索引优化查询性能
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_monitored_group_user 
                    ON monitored_users(group_id, user_id)
                """)

                # 兼容旧数据库的列平滑迁移
                for col_spec in [
                    ("group_config", "verify_mode", "TEXT DEFAULT 'keyword'"),
                    ("group_config", "custom_qa_list", "TEXT DEFAULT ''"),
                    ("group_config", "enable_initial_ban", "INTEGER DEFAULT 1"),
                    ("group_config", "enable_follow_up_ban", "INTEGER DEFAULT 1"),
                    ("group_config", "enable_violation_count", "INTEGER DEFAULT 1"),
                    ("monitored_users", "verify_question", "TEXT DEFAULT ''"),
                    ("monitored_users", "verify_answer", "TEXT DEFAULT ''"),
                ]:
                    table_name, col_name, col_type = col_spec
                    try:
                        await db.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                    except Exception:
                        pass
                
                await db.commit()
                logger.info("[AutoBan] Database initialized successfully")
    
    # ==================== 群配置管理 ====================
    
    async def get_group_config(self, group_id: str) -> Optional[Dict[str, Any]]:
        """获取群配置"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM group_config WHERE group_id = ?",
                (group_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None
    
    async def get_all_group_configs(self) -> List[Dict[str, Any]]:
        """获取所有群配置"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM group_config WHERE enabled = 1") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
    
    async def upsert_group_config(self, group_id: str, config: Dict[str, Any]) -> None:
        """插入或更新群配置"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                # 获取配置字段（排除不可更新字段）
                excluded_fields = {'group_id', 'created_at', 'updated_at'}
                fields = [k for k in config.keys() if k not in excluded_fields]
                
                if not fields:
                    return
                
                # 构建 SQL 语句
                placeholders = ', '.join(['?'] * (len(fields) + 1))
                set_clause = ', '.join([f"{f} = excluded.{f}" for f in fields])
                set_clause += ', updated_at = CURRENT_TIMESTAMP'
                
                sql = f"""
                    INSERT INTO group_config (group_id, {', '.join(fields)})
                    VALUES ({placeholders})
                    ON CONFLICT(group_id) DO UPDATE SET {set_clause}
                """
                
                values = [group_id] + [config[f] for f in fields]
                await db.execute(sql, values)
                await db.commit()
    
    async def delete_group_config(self, group_id: str) -> None:
        """删除群配置"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM group_config WHERE group_id = ?", (group_id,))
                await db.commit()
    
    async def list_enabled_groups(self) -> List[str]:
        """获取所有已启用的群号列表"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT group_id FROM group_config WHERE enabled = 1"
            ) as cursor:
                rows = await cursor.fetchall()
                return [row[0] for row in rows]
    
    # ==================== 监控用户管理 ====================
    
    async def get_monitored_user(self, group_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """获取监控用户信息"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM monitored_users WHERE group_id = ? AND user_id = ?",
                (group_id, user_id)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None
    
    async def add_monitored_user(
        self,
        group_id: str,
        user_id: str,
        ban_count: int = 0,
        verify_question: str = "",
        verify_answer: str = ""
    ) -> None:
        """添加或更新监控用户"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO monitored_users (group_id, user_id, ban_count, verify_question, verify_answer)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(group_id, user_id) DO UPDATE SET
                        ban_count = excluded.ban_count,
                        verify_question = excluded.verify_question,
                        verify_answer = excluded.verify_answer,
                        updated_at = CURRENT_TIMESTAMP
                """, (group_id, user_id, ban_count, verify_question, verify_answer))
                await db.commit()
    
    async def update_ban_count(self, group_id: str, user_id: str, ban_count: int) -> None:
        """更新用户禁言次数"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE monitored_users
                    SET ban_count = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE group_id = ? AND user_id = ?
                """, (ban_count, group_id, user_id))
                await db.commit()
    
    async def remove_monitored_user(self, group_id: str, user_id: str) -> bool:
        """移除监控用户"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "DELETE FROM monitored_users WHERE group_id = ? AND user_id = ?",
                    (group_id, user_id)
                )
                await db.commit()
                return cursor.rowcount > 0
    
    async def get_group_monitored_users(self, group_id: str) -> List[Dict[str, Any]]:
        """获取指定群的所有监控用户"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM monitored_users WHERE group_id = ? ORDER BY created_at DESC",
                (group_id,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
    
    async def get_all_monitored_users(self) -> List[Tuple[str, str, int]]:
        """获取所有监控用户（group_id, user_id, ban_count）"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT group_id, user_id, ban_count FROM monitored_users"
            ) as cursor:
                rows = await cursor.fetchall()
                return [(row[0], row[1], row[2]) for row in rows]
    
    async def clear_group_monitored_users(self, group_id: str) -> None:
        """清空指定群的所有监控用户"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM monitored_users WHERE group_id = ?", (group_id,))
                await db.commit()
    
    async def batch_remove_users(self, user_identifiers: List[Tuple[str, str]]) -> int:
        """批量移除监控用户"""
        if not user_identifiers:
            return 0
        
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                count = 0
                for group_id, user_id in user_identifiers:
                    cursor = await db.execute(
                        "DELETE FROM monitored_users WHERE group_id = ? AND user_id = ?",
                        (group_id, user_id)
                    )
                    count += cursor.rowcount
                await db.commit()
                return count
