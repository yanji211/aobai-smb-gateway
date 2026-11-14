#!/usr/bin/env node
/**
 * ui-smoke — 在 Node 里用伪 DOM 跑一遍 webui/app.js 的渲染路径。
 * 目的不是替代浏览器，而是把"元素 id 拼错、字段名写错、模板抛异常"这类
 * 只在运行时才炸的问题挡在提交前。不需要装 jsdom。
 *
 * 用法: node tools/ui-smoke.js [status.json]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "..");
const jsPath = path.join(root, "internal", "webui", "app.js");

// 一份真实结构的 /api/status 响应（可用参数覆盖为线上抓到的 JSON）
const fallback = {
  applied_state: "LAN",
  desired_state: "LAN",
  last_error: "",
  version: "0.1.0",
  uptime_seconds: 128,
  admin: false,
  shares: [
    { share_id: "main", name: "share", root: "D:\\share", writable: true, media: true }
  ],
  listeners: [
    { name: "SMB", enabled: true, ready: true, addr: "\\\\host\\share", note: "ready" },
    { name: "DLNA", enabled: false, ready: false, addr: "未实现", note: "第一版跳过" },
    { name: "WebDAV", enabled: false, ready: false, addr: "127.0.0.1:8443", note: "只读" }
  ],
  index: {
    files: 243, dirs: 15, objects: 240, versions: 12, path_history: 260,
    pending_moves: 0, events: 418, queue: 0, last_reconcile: "2026-11-03 14:50:15"
  },
  snapshot: { enabled: false, count: 0, bytes: 0, quota_gb: 200 },
  security: { webdav_bind: "127.0.0.1:8443", username: "fsgw", password_set: true }
};

const status = process.argv[2]
  ? JSON.parse(fs.readFileSync(process.argv[2], "utf8"))
  : fallback;

const writes = [];
const errors = [];

function makeEl(id) {
  const el = {
    id,
    textContent: "",
    innerHTML: "",
    hidden: false,
    disabled: false,
    className: "",
    dataset: {},
    children: [],
    style: {},
    _handlers: {},
    classList: {
      toggle() {},
      add() {},
      remove() {},
      contains() { return false; }
    },
    addEventListener(type, fn) { el._handlers[type] = fn; },
    querySelector() { return makeEl(id + ":child"); },
    closest() { return null; }
  };
  Object.defineProperty(el, "innerHTML", {
    get() { return el._html || ""; },
    set(v) { el._html = String(v); writes.push([id, String(v).length]); }
  });
  return el;
}

const registry = new Map();
const docHandlers = {};
const document = {
  getElementById(id) {
    if (!registry.has(id)) { registry.set(id, makeEl(id)); }
    return registry.get(id);
  },
  addEventListener(type, fn) { docHandlers[type] = fn; },
  createElement() { return makeEl("created"); }
};

const sandbox = {
  document,
  window: {},
  URLSearchParams,
  console: { log() {}, warn() {}, error(...a) { errors.push(a.join(" ")); } },
  location: { hash: "#smoketoken", search: "", pathname: "/", hostname: "127.0.0.1", origin: "http://127.0.0.1:8444" },
  history: { replaceState() {} },
  sessionStorage: {
    store: {},
    getItem(k) { return this.store[k] || null; },
    setItem(k, v) { this.store[k] = v; }
  },
  navigator: { clipboard: null },
  setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
  EventSource: class {
    constructor() { setTimeout(() => {}, 0); }
    addEventListener() {}
    close() {}
  },
  fetch: (url) => {
    let body = {};
    if (String(url).includes("/api/status")) { body = status; }
    else if (String(url).includes("/api/diagnose")) {
      body = [
        { level: "ok", title: "管理员权限", detail: "已提权" },
        { level: "warn", title: "匿名 SMB 客户端策略", detail: "客户端需放开来宾登录" }
      ];
    } else if (String(url).includes("/api/audit")) {
      body = [
        { time: "2026-11-03T14:50:48+08:00", source: "ctlapi", action: "switch LAN", result: "ok", detail: "applied=LAN" },
        { time: "2026-11-03T14:50:11+08:00", source: "webdav", action: "PUT", result: "deny", detail: "方法未允许" }
      ];
    } else if (String(url).includes("/api/fs/list")) {
      body = { path: "D:\\", entries: [{ name: "share", path: "D:\\share" }] };
    } else if (String(url).includes("/api/operations")) {
      body = { id: "op1", target: "LAN", stage: "done", done: true };
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify(body))
    });
  }
};

const code = fs.readFileSync(jsPath, "utf8");
try {
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: "app.js" });
} catch (e) {
  console.error("渲染时抛出异常:", e.message);
  console.error(e.stack.split("\n").slice(0, 4).join("\n"));
  process.exit(1);
}

// boot() 里是 Promise 链，给它一个 tick 跑完。
setTimeout(() => {
  if (errors.length) {
    console.error("控制台有错误输出:", errors.join(" | "));
    process.exit(1);
  }
  // 列表类区块必须写入 innerHTML；数字类区块写的是 textContent。
  const needHTML = ["svcGrid", "shareRows", "diagList", "auditRows", "spark"];
  const needText = ["kFiles", "kDirs", "kVers", "kQueue", "stateLine", "subline", "credLine"];
  const notFilled = [];
  for (const id of needHTML) {
    const el = registry.get(id);
    if (!el || !el._html) { notFilled.push(id); }
  }
  for (const id of needText) {
    const el = registry.get(id);
    if (!el || (el.textContent === "" && !el._html)) { notFilled.push(id); }
  }
  if (notFilled.length) {
    console.error("以下区块没有被填充:", notFilled.join(", "));
    process.exit(1);
  }
  // 曾经踩过的坑：.modal 自己写了 display:flex，作者样式盖掉 UA 的
  // [hidden]{display:none}，弹窗从页面加载起就一直盖在页面上。这条固化成断言。
  const css = fs.readFileSync(path.join(root, "internal", "webui", "style.css"), "utf8");
  if (!/\[hidden\]\s*\{[^}]*display\s*:\s*none/.test(css)) {
    console.error("style.css 缺少 [hidden]{display:none}，hidden 属性会被作者样式覆盖");
    process.exit(1);
  }

  console.log("UI 冒烟通过：渲染路径无异常，" + writes.length + " 次 DOM 写入，区块均已填充");
  console.log("  svcGrid 卡片数: " + (registry.get("svcGrid")._html.match(/class="svc"/g) || []).length);
  console.log("  shareRows 行数: " + (registry.get("shareRows")._html.match(/<tr>/g) || []).length);
  console.log("  auditRows 行数: " + (registry.get("auditRows")._html.match(/<tr>/g) || []).length);

  // 交互冒烟：真的触发"浏览目录"的点击处理器，确认弹窗被填上内容。
  // 之前正是因为没人跑这条路径，弹窗空着盖在页面上没被发现。
  const browseBtn = registry.get("btnBrowse");
  if (!browseBtn || !browseBtn._handlers.click) {
    console.error("btnBrowse 没有绑定 click 处理器");
    process.exit(1);
  }
  try {
    browseBtn._handlers.click();
  } catch (e) {
    console.error("点击浏览目录时抛异常:", e.message);
    process.exit(1);
  }

  setTimeout(() => {
    const modal = registry.get("modal");
    const pathEl = registry.get("modalPath");
    const listEl = registry.get("modalList");
    const problems = [];
    if (modal.hidden) { problems.push("点击后弹窗仍是 hidden"); }
    if (!pathEl || pathEl.textContent === "—" || pathEl.textContent === "") {
      problems.push("modalPath 没有被填充");
    }
    if (!listEl || !/data-go=/.test(listEl._html || "")) {
      problems.push("modalList 没有任何目录项");
    }
    if (problems.length) {
      console.error("浏览目录交互有问题:", problems.join(" | "));
      process.exit(1);
    }
    console.log("  浏览目录: path=" + pathEl.textContent +
      "，条目 " + (listEl._html.match(/class="dir"/g) || []).length + " 个");
  }, 80);
}, 100);
