// 进群禁言管理系统 - 前端交互逻辑

// Bridge 对象与环境适配
const bridge = window.AstrBotPluginPage || window.AstrBotPluginView;
const PLUGIN_NAME = "astrbot_plugin_auto_ban_new";

// 沙箱安全存储封装（防止在无 allow-same-origin 的 iframe 中访问 localStorage 触发 SecurityError）
const memoryStorage = {};
const safeStorage = {
    get(key, defaultVal = null) {
        try {
            const val = window.localStorage.getItem(key);
            return val !== null ? val : defaultVal;
        } catch (e) {
            // iframe 沙箱环境下访问 window.localStorage 会抛出 SecurityError，安全降级到内存
            return memoryStorage[key] !== undefined ? memoryStorage[key] : defaultVal;
        }
    },
    set(key, val) {
        memoryStorage[key] = val;
        try {
            window.localStorage.setItem(key, String(val));
        } catch (e) {
            // iframe 沙箱环境无 localStorage 权限，已静默降级为内存存储
        }
    }
};

// API 统一包装器
const api = {
    async get(endpoint, params = {}) {
        if (bridge && typeof bridge.apiGet === "function") {
            const res = await bridge.apiGet(endpoint, params);
            return this._unwrap(res);
        }
        // 独立调试环境降级
        const query = new URLSearchParams(params).toString();
        const url = `/${PLUGIN_NAME}/${endpoint}${query ? "?" + query : ""}`;
        const resp = await fetch(url);
        const data = await resp.json();
        return this._unwrap(data);
    },

    async post(endpoint, body = {}) {
        if (bridge && typeof bridge.apiPost === "function") {
            const res = await bridge.apiPost(endpoint, body);
            return this._unwrap(res);
        }
        // 独立调试环境降级
        const url = `/${PLUGIN_NAME}/${endpoint}`;
        const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await resp.json();
        return this._unwrap(data);
    },

    _unwrap(res) {
        if (res && typeof res === "object") {
            if ("ok" in res) {
                if (!res.ok) {
                    throw new Error(res.message || "请求失败");
                }
                return res.data !== undefined ? res.data : res;
            }
        }
        return res;
    }
};

// 全局应用状态
const state = {
    groups: [],
    currentGroupId: null,
    currentConfig: null,
    theme: "auto"
};

// 初始化应用
async function init() {
    if (bridge && typeof bridge.ready === "function") {
        try {
            await bridge.ready();
        } catch (e) {
            console.warn("[AutoBan] Bridge ready warning:", e);
        }
    }
    initTheme();
    bindEvents();
    await loadGroups();
}

// 事件绑定
function bindEvents() {
    // 刷新群列表
    document.getElementById("btn-refresh").addEventListener("click", async () => {
        await refreshGroups();
    });

    // 切换主题
    document.getElementById("btn-theme").addEventListener("click", () => {
        cycleTheme();
    });

    // 监听验证模式切换
    document.getElementById("verify_mode").addEventListener("change", () => {
        updateVerifyModeFields();
    });

    // 表单保存
    document.getElementById("config-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        await saveCurrentConfig();
    });

    // 重置配置表单
    document.getElementById("btn-reset").addEventListener("click", () => {
        if (state.currentConfig) {
            renderConfigForm(state.currentConfig);
            showToast("已恢复为当前已保存配置", "info");
        }
    });

    // 刷新监控成员列表
    document.getElementById("btn-refresh-users").addEventListener("click", async () => {
        if (state.currentGroupId) {
            await loadMonitoredUsers(state.currentGroupId);
            showToast("成员列表已刷新", "info");
        }
    });
}

// 加载群聊列表
async function loadGroups() {
    const container = document.getElementById("group-list");
    container.innerHTML = '<div class="loading-state">正在加载群聊列表...</div>';

    try {
        const groups = await api.get("api/groups");
        state.groups = Array.isArray(groups) ? groups : [];
        renderGroupList();
    } catch (err) {
        container.innerHTML = `<div class="loading-state">加载群聊失败: ${escapeHtml(err.message)}</div>`;
        showToast("加载群列表失败: " + err.message, "error");
    }
}

// 强制刷新群聊列表
async function refreshGroups() {
    showToast("正在连接协议端刷新群列表...", "info");
    try {
        const groups = await api.post("api/groups/refresh", {});
        state.groups = Array.isArray(groups) ? groups : [];
        renderGroupList();
        showToast("群聊列表已更新", "success");
    } catch (err) {
        showToast("刷新群列表失败: " + err.message, "error");
    }
}

// 渲染群列表
function renderGroupList() {
    const container = document.getElementById("group-list");
    const countEl = document.getElementById("group-count");

    countEl.textContent = state.groups.length;

    if (state.groups.length === 0) {
        container.innerHTML = '<div class="loading-state">未获取到机器人具有管理员或群主权限的群聊</div>';
        return;
    }

    container.innerHTML = state.groups.map(group => {
        const role = String(group.bot_role || "member").toLowerCase();
        let roleBadge = '<span class="role-badge member">成员</span>';
        if (role === "owner") {
            roleBadge = '<span class="role-badge owner">群主</span>';
        } else if (role === "admin") {
            roleBadge = '<span class="role-badge admin">管理员</span>';
        }

        const isActive = group.group_id === state.currentGroupId;

        return `
            <div class="group-card ${isActive ? "active" : ""}" data-group-id="${group.group_id}">
                <img class="group-avatar" src="${escapeHtml(group.avatar)}" alt="${escapeHtml(group.group_name)}"
                     onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2242%22 height=%2242%22%3E%3Crect fill=%22%23cbd5e1%22 width=%2242%22 height=%2242%22/%3E%3C/svg%3E'">
                <div class="group-card-info">
                    <div class="group-card-name">${escapeHtml(group.group_name)}</div>
                    <div class="group-card-meta">
                        <span>${escapeHtml(group.group_id)}</span>
                        ${roleBadge}
                    </div>
                </div>
            </div>
        `;
    }).join("");

    container.querySelectorAll(".group-card").forEach(card => {
        card.addEventListener("click", () => {
            const gid = card.dataset.groupId;
            selectGroup(gid);
        });
    });
}

// 选中群聊
async function selectGroup(groupId) {
    if (state.currentGroupId === groupId) return;

    state.currentGroupId = groupId;

    document.querySelectorAll(".group-card").forEach(card => {
        card.classList.toggle("active", card.dataset.groupId === groupId);
    });

    const group = state.groups.find(g => g.group_id === groupId);
    if (group) {
        document.getElementById("group-avatar").src = group.avatar;
        document.getElementById("group-name").textContent = group.group_name;
        document.getElementById("group-id-display").textContent = group.group_id;

        const roleContainer = document.getElementById("bot-role-container");
        const role = String(group.bot_role || "member").toLowerCase();
        if (role === "owner") {
            roleContainer.innerHTML = '<span class="role-badge owner">群主（具备完整管理权限）</span>';
        } else if (role === "admin") {
            roleContainer.innerHTML = '<span class="role-badge admin">管理员（具备禁言与踢人权限）</span>';
        } else {
            roleContainer.innerHTML = '<span class="role-badge member">普通成员（无管理权限，禁言功能将无法执行）</span>';
        }
    }

    document.getElementById("empty-state").style.display = "none";
    document.getElementById("config-content").style.display = "block";

    await Promise.all([
        loadGroupConfig(groupId),
        loadMonitoredUsers(groupId)
    ]);
}

// 加载单个群的配置
async function loadGroupConfig(groupId) {
    try {
        const config = await api.get(`api/group/${groupId}/config`);
        state.currentConfig = config || {};
        renderConfigForm(state.currentConfig);
    } catch (err) {
        showToast("读取群配置失败: " + err.message, "error");
    }
}

// 填充表单数据
function renderConfigForm(config) {
    document.getElementById("enabled").checked = Number(config.enabled) === 1;
    document.getElementById("enable_initial_ban").checked = Number(config.enable_initial_ban ?? 1) === 1;
    document.getElementById("initial_ban_duration").value = config.initial_ban_duration ?? 180;
    document.getElementById("enable_follow_up_monitoring").checked = Number(config.enable_follow_up_monitoring) === 1;
    document.getElementById("enable_follow_up_ban").checked = Number(config.enable_follow_up_ban ?? 1) === 1;
    document.getElementById("enable_recall_noncompliant_messages").checked = Number(config.enable_recall_noncompliant_messages) === 1;
    document.getElementById("enable_violation_count").checked = Number(config.enable_violation_count ?? 1) === 1;
    document.getElementById("enable_poke_whitelist").checked = Number(config.enable_poke_whitelist) === 1;
    document.getElementById("kick_threshold").value = config.kick_threshold ?? 7;

    document.getElementById("ban_duration_1").value = config.ban_duration_1 ?? 180;
    document.getElementById("ban_duration_2").value = config.ban_duration_2 ?? 180;
    document.getElementById("ban_duration_3").value = config.ban_duration_3 ?? 600;
    document.getElementById("ban_duration_4").value = config.ban_duration_4 ?? 3600;

    document.getElementById("verify_mode").value = config.verify_mode || "keyword";
    document.getElementById("whitelist_keywords").value = config.whitelist_keywords ?? "我已阅读并同意遵守群规";
    document.getElementById("custom_qa_list").value = config.custom_qa_list ?? "";
    updateVerifyModeFields();

    document.getElementById("welcome_message").value = config.welcome_message ?? "";
    document.getElementById("whitelist_success_message").value = config.whitelist_success_message ?? "";
    document.getElementById("poke_whitelist_message").value = config.poke_whitelist_message ?? "";
    document.getElementById("kick_message").value = config.kick_message ?? "";

    document.getElementById("ban_message_1").value = config.ban_message_1 ?? "";
    document.getElementById("ban_message_2").value = config.ban_message_2 ?? "";
    document.getElementById("ban_message_3").value = config.ban_message_3 ?? "";
    document.getElementById("ban_message_4").value = config.ban_message_4 ?? "";
}

// 切换验证模式输入框显示状态
function updateVerifyModeFields() {
    const modeEl = document.getElementById("verify_mode");
    if (!modeEl) return;
    const mode = modeEl.value;
    const kwField = document.getElementById("field-whitelist-keywords");
    const qaField = document.getElementById("field-custom-qa");
    const mathField = document.getElementById("field-math-hint");

    if (kwField) kwField.style.display = mode === "keyword" ? "block" : "none";
    if (qaField) qaField.style.display = mode === "custom_qa" ? "block" : "none";
    if (mathField) mathField.style.display = (mode === "math_add_sub" || mode === "math_mul_div") ? "block" : "none";
}

// 保存配置
async function saveCurrentConfig() {
    if (!state.currentGroupId) return;

    const payload = {
        group_id: state.currentGroupId,
        enabled: document.getElementById("enabled").checked ? 1 : 0,
        enable_initial_ban: document.getElementById("enable_initial_ban").checked ? 1 : 0,
        initial_ban_duration: parseInt(document.getElementById("initial_ban_duration").value, 10) || 0,
        enable_follow_up_monitoring: document.getElementById("enable_follow_up_monitoring").checked ? 1 : 0,
        enable_follow_up_ban: document.getElementById("enable_follow_up_ban").checked ? 1 : 0,
        enable_recall_noncompliant_messages: document.getElementById("enable_recall_noncompliant_messages").checked ? 1 : 0,
        enable_violation_count: document.getElementById("enable_violation_count").checked ? 1 : 0,
        enable_poke_whitelist: document.getElementById("enable_poke_whitelist").checked ? 1 : 0,
        kick_threshold: parseInt(document.getElementById("kick_threshold").value, 10) || 7,

        ban_duration_1: parseInt(document.getElementById("ban_duration_1").value, 10) || 180,
        ban_duration_2: parseInt(document.getElementById("ban_duration_2").value, 10) || 180,
        ban_duration_3: parseInt(document.getElementById("ban_duration_3").value, 10) || 600,
        ban_duration_4: parseInt(document.getElementById("ban_duration_4").value, 10) || 3600,

        verify_mode: document.getElementById("verify_mode").value,
        whitelist_keywords: document.getElementById("whitelist_keywords").value.trim(),
        custom_qa_list: document.getElementById("custom_qa_list").value.trim(),

        welcome_message: document.getElementById("welcome_message").value.trim(),
        whitelist_success_message: document.getElementById("whitelist_success_message").value.trim(),
        poke_whitelist_message: document.getElementById("poke_whitelist_message").value.trim(),
        kick_message: document.getElementById("kick_message").value.trim(),

        ban_message_1: document.getElementById("ban_message_1").value.trim(),
        ban_message_2: document.getElementById("ban_message_2").value.trim(),
        ban_message_3: document.getElementById("ban_message_3").value.trim(),
        ban_message_4: document.getElementById("ban_message_4").value.trim()
    };

    try {
        const saved = await api.post(`api/group/${state.currentGroupId}/config`, payload);
        state.currentConfig = saved;
        showToast("群配置已成功保存", "success");
    } catch (err) {
        showToast("保存配置失败: " + err.message, "error");
    }
}

// 加载指定群的监控用户
async function loadMonitoredUsers(groupId) {
    const container = document.getElementById("monitored-users");
    container.innerHTML = '<div class="loading-state">正在查询监控名单...</div>';

    try {
        const users = await api.get(`api/group/${groupId}/monitored_users`);
        renderMonitoredUsers(Array.isArray(users) ? users : []);
    } catch (err) {
        container.innerHTML = `<div class="loading-state">加载监控成员失败: ${escapeHtml(err.message)}</div>`;
    }
}

// 渲染监控用户列表
function renderMonitoredUsers(users) {
    const container = document.getElementById("monitored-users");

    if (users.length === 0) {
        container.innerHTML = '<div class="loading-state">当前群聊暂无处于监控状态的成员</div>';
        return;
    }

    container.innerHTML = users.map(user => `
        <div class="user-card">
            <img class="user-avatar" src="${escapeHtml(user.avatar)}" alt="${escapeHtml(user.nickname)}"
                 onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2236%22 height=%2236%22%3E%3Ccircle cx=%2218%22 cy=%2218%22 r=%2218%22 fill=%22%23cbd5e1%22/%3E%3C/svg%3E'">
            <div class="user-info">
                <div class="user-nickname">${escapeHtml(user.nickname)}</div>
                <div class="user-meta">QQ: ${escapeHtml(user.user_id)} | 违规次数: ${user.ban_count}</div>
            </div>
            <button type="button" class="btn-danger btn-sm btn-remove-user" data-user-id="${user.user_id}">
                解除监控
            </button>
        </div>
    `).join("");

    container.querySelectorAll(".btn-remove-user").forEach(btn => {
        btn.addEventListener("click", async () => {
            const uid = btn.dataset.userId;
            await removeMonitoredUser(uid);
        });
    });
}

// 手动解除指定成员的监控
async function removeMonitoredUser(userId) {
    if (!state.currentGroupId) return;

    if (!confirm(`确定要提前解除对用户 ${userId} 的监控吗？`)) {
        return;
    }

    try {
        await api.post(`api/group/${state.currentGroupId}/monitored_users/${userId}/remove`, {});
        showToast(`已解除对用户 ${userId} 的监控`, "success");
        await loadMonitoredUsers(state.currentGroupId);
    } catch (err) {
        showToast("解除监控失败: " + err.message, "error");
    }
}

// 主题管理（适配 AstrBot iframe 沙箱）
function initTheme() {
    if (bridge && typeof bridge.getContext === "function") {
        try {
            const ctx = bridge.getContext();
            if (ctx && typeof ctx.isDark === "boolean") {
                document.documentElement.setAttribute("data-theme", ctx.isDark ? "dark" : "light");
            }
        } catch (e) {}
    }
    if (bridge && typeof bridge.onContext === "function") {
        try {
            bridge.onContext((ctx) => {
                if (ctx && typeof ctx.isDark === "boolean") {
                    document.documentElement.setAttribute("data-theme", ctx.isDark ? "dark" : "light");
                }
            });
        } catch (e) {}
    }

    const currentTheme = document.documentElement.getAttribute("data-theme");
    if (!currentTheme) {
        const savedTheme = safeStorage.get("autoban_theme", "auto");
        applyTheme(savedTheme);
    }
}

function applyTheme(theme) {
    if (theme === "auto") {
        const isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
    } else {
        document.documentElement.setAttribute("data-theme", theme);
    }
}

function cycleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const nextTheme = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    safeStorage.set("autoban_theme", nextTheme);

    const labels = { light: "浅色模式", dark: "深色模式" };
    showToast(`主题已切换为: ${labels[nextTheme]}`, "info");
}

// 消息提示 Toast
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(-6px)";
        setTimeout(() => toast.remove(), 250);
    }, 2800);
}

// 安全 HTML 字符转义
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = String(text ?? "");
    return div.innerHTML;
}

// 页面加载完成后启动
document.addEventListener("DOMContentLoaded", init);
