# 项目结构说明

```
astrbot_plugin_auto_ban_new/
├── main.py                   # 插件主入口，包含所有事件处理逻辑
├── database.py               # SQLite 数据库管理模块
├── web_controller.py         # WebUI 后端 API 控制器
├── metadata.yaml             # 插件元数据配置
├── requirements.txt          # Python 依赖声明
├── README.md                 # 中文文档
├── CHANGELOG.md              # 版本更新日志
├── LICENSE                   # 开源许可证
└── pages/                    # WebUI 前端视图目录
    └── settings/             # 视图页面模块
        ├── index.html        # 主页面结构
        ├── styles.css        # 现代化样式表
        └── app.js            # 前端交互与 Bridge 通信逻辑
```

## 核心模块说明

### main.py
插件主入口，包含以下功能：
- 插件初始化和生命周期管理
- 新成员入群事件处理
- 消息监听和违规检测
- 戳一戳事件处理
- 成员退群事件处理
- 后台定期巡检任务

### database.py
数据库管理模块，提供：
- 数据库初始化和表结构创建
- 群配置的 CRUD 操作
- 监控用户的 CRUD 操作
- 异步数据库操作接口
- 并发安全的事务控制

### web_controller.py
WebUI 后端 API 控制器，提供以下接口：
- GET  /api/groups - 获取群列表
- POST /api/groups/refresh - 刷新群列表
- GET  /api/group/{group_id}/config - 获取群配置
- POST /api/group/{group_id}/config - 保存群配置
- GET  /api/group/{group_id}/monitored_users - 获取监控用户
- DELETE /api/group/{group_id}/monitored_users/{user_id} - 移除监控

### pages/
WebUI 前端资源目录：
- **index.html** - 主页面结构，包含群列表和配置表单
- **styles.css** - 现代化 UI 样式，支持浅色/深色主题
- **app.js** - 前端应用逻辑，处理用户交互和 API 调用

## 数据库结构

### group_configs 表
存储每个群的独立配置：
```sql
CREATE TABLE group_configs (
    group_id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    initial_ban_duration INTEGER DEFAULT 180,
    enable_follow_up_monitoring INTEGER DEFAULT 1,
    enable_recall_noncompliant_messages INTEGER DEFAULT 0,
    enable_poke_whitelist INTEGER DEFAULT 1,
    kick_threshold INTEGER DEFAULT 7,
    ban_duration_1 INTEGER DEFAULT 180,
    ban_duration_2 INTEGER DEFAULT 180,
    ban_duration_3 INTEGER DEFAULT 600,
    ban_duration_4 INTEGER DEFAULT 3600,
    whitelist_keywords TEXT DEFAULT '我已阅读并同意遵守群规',
    welcome_message TEXT,
    whitelist_success_message TEXT,
    poke_whitelist_message TEXT,
    kick_message TEXT,
    ban_message_1 TEXT,
    ban_message_2 TEXT,
    ban_message_3 TEXT,
    ban_message_4 TEXT,
    created_at TEXT,
    updated_at TEXT
)
```

### monitored_users 表
存储当前监控的用户：
```sql
CREATE TABLE monitored_users (
    group_id TEXT,
    user_id TEXT,
    ban_count INTEGER DEFAULT 0,
    join_time TEXT,
    last_violation_time TEXT,
    PRIMARY KEY (group_id, user_id)
)
```

## API 接口说明

所有 API 返回格式统一为：
```json
{
    "ok": true,
    "message": "Success",
    "data": {...}
}
```

错误响应：
```json
{
    "ok": false,
    "message": "错误描述",
    "data": null
}
```

## 开发说明

### 添加新功能
1. 在 `database.py` 中添加数据库操作方法
2. 在 `web_controller.py` 中添加 API 端点
3. 在 `main.py` 中添加事件处理逻辑
4. 在 `pages/app.js` 中添加前端交互
5. 更新文档和 CHANGELOG

### 数据库迁移
如需修改表结构，在 `database.py` 的 `initialize()` 方法中添加 ALTER TABLE 语句。

### 样式定制
修改 `pages/styles.css` 中的 CSS 变量即可调整主题配色：
```css
:root {
    --accent: #8b5cf6;        /* 主题色 */
    --bg-deep: #ffffff;       /* 背景色 */
    --text-primary: #1a1a1a;  /* 文字颜色 */
    /* ... */
}
```

### 测试建议
1. 使用小群进行功能测试
2. 测试 Bot 权限不足的场景
3. 测试并发场景（多用户同时入群）
4. 测试数据库并发写入
5. 测试插件热重载

## 性能优化

### 已实施的优化
- 群列表缓存（90 秒）
- 异步数据库操作
- 后台任务定期巡检（5 分钟）
- 事件处理优先级控制

### 未来优化方向
- 添加内存缓存层（Redis）
- 批量数据库操作
- WebSocket 实时推送
- 群配置预加载

## 安全考虑

### 已实施的安全措施
- SQL 参数化查询，防止注入
- API 输入验证
- 数据库事务保护
- 并发锁控制

### 注意事项
- 不要在日志中输出敏感信息
- 定期备份数据库文件
- 限制 API 访问频率（未来版本）
- 添加管理员身份验证（未来版本）
