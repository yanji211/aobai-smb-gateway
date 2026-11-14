(function () {
  "use strict";

  // 两条通道：
  //   1) 人：用户名 + 口令，登录后服务端发会话 cookie（fsgw_sess），页面啥都不用存；
  //   2) 机器：token 走 URL fragment（不进 Referer、不进访问日志）或 ?token=，
  //      由 `fsgw ui` 和脚本带进来，之后每个请求放 X-FSGW-Token 头。
  //
  // 只有带了 token 才需要在前端存东西；口令登录的凭据在 HttpOnly cookie 里，
  // JS 读不到，被盗脚本也拿不走。
  var TOKEN = "";
  var hash = location.hash.replace(/^#/, "");
  var qs = new URLSearchParams(location.search || "");
  var queryToken = qs.get("token") || "";

  // 存令牌的包装：隐私模式 / 禁用存储时 localStorage 会抛异常，不能让整页挂掉。
  var store = {
    get: function (k) {
      try { var v = localStorage.getItem(k); if (v) { return v; } } catch (e) {}
      try { return sessionStorage.getItem(k) || ""; } catch (e) { return ""; }
    },
    set: function (k, v, remember) {
      try { sessionStorage.setItem(k, v); } catch (e) {}
      try {
        if (remember) { localStorage.setItem(k, v); } else { localStorage.removeItem(k); }
      } catch (e) {}
    },
    clear: function (k) {
      try { localStorage.removeItem(k); } catch (e) {}
      try { sessionStorage.removeItem(k); } catch (e) {}
    }
  };

  if (hash) {
    TOKEN = hash;
    store.set("fsgw_token", hash, true);
    try { history.replaceState(null, "", location.pathname); } catch (e) {}
  } else if (queryToken) {
    TOKEN = queryToken;
    store.set("fsgw_token", queryToken, false);
  } else {
    TOKEN = store.get("fsgw_token");
  }

  var el = function (id) { return document.getElementById(id); };
  var cur = { state: "OFF", busy: false, pendingTarget: "", spark: [] };
  var loggedOut = false; // 收到 401 后停掉轮询，等用户重新登录
  var lastStatus = null; // 最近一次 /api/status，切换过程中做局部渲染要用
  var busyWatchdog = null; // busy 复位兜底：界面绝不能因为一个异常就永久点不动

  // ---------- 登录 ----------

  function showGate(msg) {
    var g = el("gate");
    if (!g) { return; }
    g.hidden = false;
    var m = el("gateMsg");
    m.textContent = msg || "";
    m.className = "grow tiny" + (msg ? " err" : "");
    var p = el("gatePass");
    if (p) { p.value = ""; }
    var u = el("gateUser");
    var target = (u && !u.value.trim()) ? u : p;
    setTimeout(function () { try { target.focus(); } catch (e) {} }, 30);
  }

  function hideGate() {
    var g = el("gate");
    if (g) { g.hidden = true; }
  }

  function setUser(name) {
    var pill = el("adminPill");
    if (name && pill) { pill.title = "当前登录：" + name; }
  }

  // 口令登录：服务端拿共享账号校验（WebDAV / SMB），成功后种 HttpOnly cookie。
  function submitGate(ev) {
    if (ev) { ev.preventDefault(); }
    var user = (el("gateUser").value || "").trim();
    var pass = el("gatePass").value || "";
    if (!user) { showGate("先填用户名"); return; }
    if (!pass) { showGate("再填口令"); return; }
    var msg = el("gateMsg");
    msg.textContent = "验证中…";
    msg.className = "grow tiny";
    var remember = !!(el("gateRemember") && el("gateRemember").checked);
    fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: user, password: pass, remember: remember })
    }).then(function (r) {
      return r.text().then(function (txt) {
        var d = null;
        try { d = txt ? JSON.parse(txt) : null; } catch (e) {}
        if (r.ok) { return d || {}; }
        throw new Error((d && d.error) || ("HTTP " + r.status));
      });
    }).then(function (d) {
      TOKEN = "";
      store.clear("fsgw_token");
      loggedOut = false;
      setUser(d.user || user);
      hideGate();
      banner("");
      afterLogin();
    }).catch(function (e) {
      showGate(e.message || "登录失败");
    });
  }

  // 令牌登录：老通道，留给脚本和"忘了口令但能上服务器 cat 一把"的场合。
  function tryToken(tok) {
    return fetch("/api/status", { headers: { "X-FSGW-Token": tok } }).then(function (r) {
      if (r.status === 401) { throw new Error("令牌不对（服务端拒了），再核对一遍"); }
      if (!r.ok) { throw new Error("服务端返回 HTTP " + r.status); }
      return r.json();
    });
  }

  function submitTokenLogin() {
    var t = (el("gateToken").value || "").trim();
    if (!t) { showGate("先粘贴令牌"); return; }
    var msg = el("gateMsg");
    msg.textContent = "验证中…";
    msg.className = "grow tiny";
    tryToken(t).then(function () {
      TOKEN = t;
      store.set("fsgw_token", t, true);
      loggedOut = false;
      hideGate();
      banner("");
      afterLogin();
    }).catch(function (e) {
      showGate(e.message || "令牌不对");
    });
  }

  function afterLogin() {
    refresh().then(function () { startLoops(); });
  }

  function handleUnauthorized() {
    if (loggedOut) { return; }
    loggedOut = true;
    stopLoops();
    showGate("登录已过期，请重新登录");
  }

  function toast(msg) {
    var t = el("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.classList.remove("show"); }, 1800);
  }

  function banner(msg, isErr) {
    var b = el("banner");
    if (!msg) { b.hidden = true; return; }
    b.hidden = false;
    b.textContent = msg;
    b.className = "banner" + (isErr ? " err" : "");
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (TOKEN) { opts.headers["X-FSGW-Token"] = TOKEN; }
    if (opts.body) { opts.headers["Content-Type"] = "application/json"; }
    // 同源请求默认带 cookie；显式写出来是为了跨浏览器一致。
    opts.credentials = "same-origin";
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = { raw: txt }; }
        if (r.status === 401) {
          handleUnauthorized();
          throw new Error("unauthorized");
        }
        if (!r.ok) {
          throw new Error((data && data.error) || ("HTTP " + r.status));
        }
        return data;
      });
    });
  }

  var STATE_TEXT = {
    OFF: ["全部服务已停止", "无监听端口、无防火墙规则；索引仍在后台维护"],
    LAN: ["局域网可访问", "SMB 已就绪，外部面关闭"],
    WAN: ["仅外部可访问", "WebDAV 只读面已就绪，局域网面关闭"],
    ALL: ["全部面已开启", "局域网与外部同时暴露，请确认外部口令已设置"]
  };

  // ---------- 渲染 ----------

  function render(st) {
    lastStatus = st;
    cur.state = st.applied_state;
    el("subline").textContent = "共享根 " + (st.shares[0] ? st.shares[0].root : "—") +
      " · 运行 " + fmtUptime(st.uptime_seconds);
    el("verPill").textContent = "v" + st.version;
    var ap = el("adminPill");
    ap.textContent = st.admin ? "已提权" : "未提权";
    ap.className = "pill " + (st.admin ? "ok" : "warn");

    renderSync(st.sync);
    Array.prototype.forEach.call(el("seg").children, function (b) {
      b.classList.toggle("on", b.dataset.s === st.applied_state);
      b.disabled = cur.busy;
    });

    var t = STATE_TEXT[st.applied_state] || ["未知状态", ""];
    var detail = t[1];
    // LAN 的副标题不能写死"已就绪"：SMB 可能因为没提权/445 被占而没起来，
    // 这里按 listeners 里的真实 ready 说话，免得界面报喜不报忧。
    if (st.applied_state === "LAN") {
      var smb = (st.listeners || []).filter(function (l) { return l.name === "SMB"; })[0];
      detail = (smb && smb.ready)
        ? "SMB 已就绪，外部面关闭"
        : "SMB 未就绪（" + ((smb && smb.note) || "请查看服务面说明") + "），DLNA / 快同步可用";
    }
    var line = "<b>" + t[0] + "</b> · " + detail;
    if (st.last_error) {
      line += ' · <span class="warn">上次失败：' + esc(st.last_error) + "</span>";
    }
    el("stateLine").innerHTML = line;

    renderServices(st);
    renderShares(st);
    renderSecurity(st);
    renderSMBAuth(st);
    renderIndex(st);
  }

  // 口令本身不回传，只回"是否已设置"。
  function renderSecurity(st) {
    var sec = st.security || {};
    var u = el("wdUser");
    if (u && !u.value) { u.value = sec.username || ""; }
    el("credLine").textContent = sec.webdav_bind
      ? ("监听 " + sec.webdav_bind + " · 用户名 " + (sec.username || "—") +
         " · " + (sec.password_set ? "口令已设置" : "口令未设置"))
      : "—";
  }

  // ---------- SMB 客户端 ----------

  function fmtAgo(t) {
    if (!t) { return "—"; }
    var d = (Date.now() - new Date(t).getTime()) / 1000;
    if (d < 0) { d = 0; }
    if (d < 60) { return Math.floor(d) + " 秒"; }
    if (d < 3600) { return Math.floor(d / 60) + " 分钟"; }
    if (d < 86400) { return Math.floor(d / 3600) + " 小时"; }
    return Math.floor(d / 86400) + " 天";
  }

  function fmtStamp(t) {
    if (!t) { return "—"; }
    return String(t).replace("T", " ").slice(0, 19);
  }

  // 这里只展示"谁能进、谁在线、谁被拒"，不回传任何口令或哈希。
  function renderSMBAuth(st) {
    var sb = st.smb_auth || {};
    var accts = sb.accounts || [];
    el("smbLine").textContent = sb.path
      ? ("账号表 " + sb.path + " · 已登记 " + accts.length + " 个 · 在线 " +
         (sb.sessions || []).length + " 条连接")
      : "—";

    el("smbAcctRows").innerHTML = accts.length ? accts.map(function (a) {
      var action = a.source === "console"
        ? '<button class="btn mini ghost" data-smbdel="' + esc(a.name) + '">移除</button>'
        : '<span class="tiny">在 config.yaml 里改</span>';
      return "<tr><td><code class=\"mono\">" + esc(a.name) + "</code></td>" +
        "<td>" + esc(a.note || "") + "</td>" +
        "<td>" + esc(fmtStamp(a.added_at)) + "</td>" +
        "<td>" + (a.source === "console" ? "面板" : "配置") + "</td>" +
        "<td>" + action + "</td></tr>";
    }).join("") : '<tr><td colspan="5" class="tiny">还没有登记客户端账号（此时任何设备都能以匿名/来宾身份进来）</td></tr>';

    var sess = sb.sessions || [];
    el("smbSessRows").innerHTML = sess.length ? sess.map(function (s) {
      var who = s.guest
        ? '<span class="tag ro">来宾</span>'
        : '<code class="mono">' + esc(s.user || "认证中") + "</code>";
      // 接入端一列解决的是"这台设备为什么连不上"：看到 macOS 就去查签名，
      // 看到内核 CIFS 就去查文件系统信息类，不用从抓包猜。
      var kind = s.client_label
        ? '<span class="tag" title="' + esc(s.client || "") + '">' + esc(s.client_label) + "</span>"
        : '<span class="tiny">识别中</span>';
      return "<tr><td><code class=\"mono\">" + esc(s.remote) + "</code></td>" +
        "<td>" + kind + "</td><td>" + who + "</td><td>" + fmtAgo(s.since) + "</td>" +
        "<td>" + esc((s.trees || []).join(", ") || "—") + "</td></tr>";
    }).join("") : '<tr><td colspan="5" class="tiny">当前没有在线连接</td></tr>';

    var tries = (sb.attempts || []).slice(0, 12);
    el("smbTryList").innerHTML = tries.length ? tries.map(function (a) {
      var word = a.result === "ok" ? "通过" : (a.result === "denied" ? "被拒" : "来宾");
      return '<button class="chip" data-smbtry="' + esc(a.user) + '">' +
        esc(a.user) + " · " + word + " · " + fmtAgo(a.at) + "</button>";
    }).join("") : '<span class="tiny">还没有登录尝试</span>';
  }

  function fmtUptime(s) {    if (s < 60) { return s + " 秒"; }
    if (s < 3600) { return Math.floor(s / 60) + " 分钟"; }
    return Math.floor(s / 3600) + " 小时 " + Math.floor((s % 3600) / 60) + " 分";
  }

  function esc(s) {
    // 引号也要转义：这些值有的会落进 data-* 属性（设备名、路径、共享 ID），
    // 名字里带个引号就会把属性截断，按钮点了没反应。
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function renderServices(st) {
    var host = location.hostname;
    var shareName = st.shares[0] ? st.shares[0].name : "share";
    var cards = st.listeners.map(function (l) {
      var up = l.enabled && l.ready;
      var addr = l.addr;
      if (l.name === "SMB" && up) {
        addr = "smb://" + host + "/" + shareName;
      } else if (l.name === "WebDAV" && up) {
        addr = "http://" + l.addr + "/" + shareName + "/";
      }
      var pill = up
        ? '<span class="pill-dot ok"><i></i>就绪</span>'
        : '<span class="pill-dot off"><i></i>停止</span>';
      // 设备名这类"看得见、能改"的属性单独一行：电视/手机里显示的就是它。
      var extra = "";
      if (l.extra) {
        extra = '<div class="svc-extra"><span class="lbl">' + esc(l.extra.label) + "</span>" +
          '<span class="val">' + esc(l.extra.value) + "</span>" +
          (l.extra.action === "dlna-name"
            ? '<button class="btn mini ghost" data-dlna-name="' + esc(l.extra.value) + '">改名</button>'
            : "") +
          "</div>";
      }
      return '<div class="svc">' +
        '<div class="row1"><span class="name">' + l.name + "</span>" + pill + "</div>" +
        '<div class="addr">' + esc(addr) + "</div>" +
        '<div class="note">' + esc(l.note || "") + "</div>" +
        extra +
        '<div><button class="btn mini" data-copy="' + esc(addr) + '">复制地址</button></div>' +
        "</div>";
    });
    el("svcGrid").innerHTML = cards.join("");
  }

  function renderShares(st) {
    el("shareRows").innerHTML = st.shares.map(function (s) {
      var tags = '<span class="tag ' + (s.writable ? "rw" : "ro") + '">' +
        (s.writable ? "可读写" : "只读") + "</span>";
      if (s.media) { tags += '<span class="tag media">媒体</span>'; }
      var root = '<code class="mono">' + esc(s.root) + "</code>";
      if (s.rebuilding) {
        root += ' <span class="tag warn">重建索引中…</span>';
      }
      return "<tr><td>" + root + "</td>" +
        "<td>" + (s.writable ? "可读写" : "只读") + "</td>" +
        "<td>" + tags + "</td>" +
        '<td><button class="btn mini" data-share="' + esc(s.share_id) +
        '" data-root="' + esc(s.root) + '"' + (s.rebuilding ? " disabled" : "") +
        ">更换目录</button></td></tr>";
    }).join("");
  }

  // 换共享根：服务端写配置、清旧索引、重启对外面，索引在后台重建。
  // 地址（\\主机\share）不变，换的是它后面的目录，所以这里要提醒一句。
  function changeShareRoot(id, root) {
    api("/api/shares/" + encodeURIComponent(id) + "/root", {
      method: "PUT",
      body: JSON.stringify({ root: root })
    }).then(function (res) {
      banner("共享目录已切到 " + res.root + "，正在后台重建索引（大目录要几分钟）。" +
        "共享地址不变，内容换成新目录。", false);
      refresh();
    }).catch(function (e) {
      toast("改不了：" + e.message);
    });
  }

  function renderIndex(st) {
    var i = st.index || {};
    el("kFiles").textContent = fmt(i.files);
    el("kDirs").textContent = fmt(i.dirs);
    el("kVers").textContent = fmt(i.versions);
    el("kHist").textContent = fmt(i.path_history);
    el("kEvents").textContent = fmt(i.events);
    el("kQueue").textContent = fmt(i.queue);
    el("reconcileLine").textContent = i.last_reconcile
      ? "最近一次子树重建：" + i.last_reconcile
      : "尚未发生子树重建（无溢出事件）";

    cur.spark.push(i.events || 0);
    if (cur.spark.length > 30) { cur.spark.shift(); }
    drawSpark(cur.spark);
  }

  function fmt(n) {
    if (n === undefined || n === null) { return "—"; }
    return Number(n).toLocaleString("zh-CN");
  }

  function drawSpark(pts) {
    if (!pts.length) { return; }
    var base = pts[0], max = 1;
    pts.forEach(function (p) { max = Math.max(max, p - base); });
    var d = pts.map(function (v, idx) {
      var x = pts.length === 1 ? 0 : (idx / (pts.length - 1)) * 300;
      var y = 44 - ((v - base) / max) * 36;
      return (idx ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }).join(" ");
    el("spark").innerHTML =
      '<path d="' + d + ' L300 46 L0 46 Z" fill="rgba(37,99,235,.10)"/>' +
      '<path d="' + d + '" fill="none" stroke="#2563eb" stroke-width="1.6" stroke-linejoin="round"/>';
  }

  function renderDiag(items) {
    el("diagList").innerHTML = items.map(function (it) {
      var mark = it.level === "ok" ? "✓" : it.level === "warn" ? "!" : "×";
      return '<div class="item"><span class="ico ' + it.level + '">' + mark + "</span>" +
        "<span><b>" + esc(it.title) + '</b> <span class="t">' + esc(it.detail) + "</span></span></div>";
    }).join("");
  }

  function renderAudit(rows) {
    if (!rows || !rows.length) {
      el("auditRows").innerHTML = '<tr><td colspan="5" class="tiny" style="text-align:center;padding:20px">暂无记录</td></tr>';
      return;
    }
    el("auditRows").innerHTML = rows.slice().reverse().map(function (r) {
      var t = (r.time || "").replace("T", " ").replace(/\..*/, "").replace(/^\d{4}-\d\d-\d\d /, "");
      var cls = r.result === "ok" ? "res-ok" : r.result === "deny" ? "res-deny" : "res-err";
      var label = r.result === "ok" ? "成功" : r.result === "deny" ? "拒绝" : "错误";
      return "<tr><td class=\"tiny\">" + esc(t) + "</td>" +
        "<td><code class=\"mono\">" + esc(r.source || "") + "</code></td>" +
        "<td>" + esc(r.action || "") + "</td>" +
        '<td class="' + cls + '">' + label + "</td>" +
        '<td class="tiny">' + esc(r.detail || r.path || "") + "</td></tr>";
    }).join("");
  }

  // ---------- 开关 ----------

  function applyState(target) {
    if (cur.busy || target === cur.state) { return; }
    cur.busy = true;
    armBusyWatchdog();
    // 从"提交中"到操作完成，期间一律用 try 包住：任何渲染异常都必须
    // 把 busy 放回去，否则按钮会永久置灰、点什么都没反应（界面像卡死）。
    try {
      if (lastStatus) { renderSync(lastStatus.sync); }
      Array.prototype.forEach.call(el("seg").children, function (b) { b.disabled = true; });
      el("stateLine").innerHTML = '<span class="warn">正在切换：</span> 提交中…';
    } catch (err) {
      busyOff();
      banner("界面出错：" + (err && err.message ? err.message : err), true);
      refresh();
      return;
    }

    var body = { state: target };
    if (target === "WAN" || target === "ALL") { body.confirm = target; }

    api("/api/switch", { method: "POST", body: JSON.stringify(body) })
      .then(function (res) {
        pollOperation(res.operation_id);
      })
      .catch(function (e) {
        busyOff();
        banner("切换失败：" + e.message, true);
        refresh();
      });
  }

  // busyOff 统一收口：解锁按钮 + 撤掉兜底定时器。
  function busyOff() {
    cur.busy = false;
    if (busyWatchdog) { clearTimeout(busyWatchdog); busyWatchdog = null; }
  }

  // 最长等 90 秒（445 接管最坏二十几秒 + 服务端回滚），到点无条件解锁，
  // 免得一个卡住的请求把整个面板锁死。
  function armBusyWatchdog() {
    if (busyWatchdog) { clearTimeout(busyWatchdog); }
    busyWatchdog = setTimeout(function () {
      busyWatchdog = null;
      if (!cur.busy) { return; }
      cur.busy = false;
      banner("切换等待超时，界面已解锁。服务端可能仍在后台切换，请稍后刷新查看。", true);
      refresh();
    }, 90000);
  }

  function pollOperation(id) {
    var tries = 0;
    function tick() {
      api("/api/operations/" + id).then(function (op) {
        tries++;
        // 上限给到 60 秒：切 LAN 要先让 LanmanServer 让出 445，
        // 服务停稳 + 端口释放最坏能到二十几秒，早先 21 秒的上限会让
        // 界面在操作还没完成时就宣布失败/显示回 OFF。
        if (!op.done && tries < 200) {
          el("stateLine").innerHTML = '<span class="warn">正在切换：</span> ' + stageText(op.stage);
          setTimeout(tick, 300);
          return;
        }
        cur.busy = false;
        if (busyWatchdog) { clearTimeout(busyWatchdog); busyWatchdog = null; }
        if (op.error) {
          banner("切换失败（stage=" + op.stage + "）：" + op.error, true);
        } else if (op.done) {
          banner("");
          toast("已切换为 " + op.target);
        } else {
          banner("切换仍在后台进行（" + stageText(op.stage) + "），稍后自动刷新结果", false);
        }
        refresh();
      }).catch(function () {
        busyOff();
        refresh();
      });
    }
    tick();
  }

  function stageText(stage) {
    return {
      queued: "排队中",
      firewall: "更新防火墙规则",
      listener: "启动/停止监听（SMB 接管 445 可能要十几秒）",
      selfcheck: "自检",
      teardown: "拆除旧状态",
      done: "完成"
    }[stage] || stage;
  }

  el("seg").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b || cur.busy) { return; }
    var target = b.dataset.s;
    if (target === cur.state) { return; }
    if ((target === "WAN" || target === "ALL") && cur.state === "OFF") {
      el("confirmText").innerHTML = "即将开启 <b>" + target + "</b>，外部网络将可以访问本机共享。确认？";
      el("confirmStrip").classList.add("show");
      cur.pendingTarget = target;
      return;
    }
    el("confirmStrip").classList.remove("show");
    applyState(target);
  });

  el("confirmCancel").addEventListener("click", function () {
    el("confirmStrip").classList.remove("show");
    cur.pendingTarget = "";
  });

  el("confirmOk").addEventListener("click", function () {
    el("confirmStrip").classList.remove("show");
    if (cur.pendingTarget) { applyState(cur.pendingTarget); }
    cur.pendingTarget = "";
  });

  el("btnAllOff").addEventListener("click", function () {
    if (cur.state === "OFF") { toast("已经是关闭状态"); return; }
    applyState("OFF");
  });

  // 退出程序：先把共享拆干净再结束进程，所以这里不是"关页面"而是真的停服务。
  el("btnQuit").addEventListener("click", function () {
    var ok = window.confirm(
      "退出会先关闭全部共享（SMB / DLNA / WebDAV / 防火墙规则），然后结束 fsgw 进程。\n" +
      "托盘图标和本控制台都会消失。确定退出？"
    );
    if (!ok) { return; }
    el("btnQuit").disabled = true;
    banner("正在退出：先关闭共享，再结束进程…", false);
    api("/api/quit", { method: "POST" }).then(function () {
      banner("fsgw 已退出。本页可以关闭；下次用 fsgw.exe run 或托盘菜单启动。", false);
    }).catch(function (e) {
      // 进程结束时连接可能被重置，这不算失败
      if (e && e.message === "unauthorized") { return; }
      banner("fsgw 已退出。本页可以关闭；下次用 fsgw.exe run 或托盘菜单启动。", false);
    });
  });

  document.addEventListener("click", function (e) {
    var c = e.target.closest("[data-copy]");
    if (!c) { return; }
    var txt = c.dataset.copy;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(txt).then(function () { toast("已复制：" + txt); },
        function () { toast(txt); });
    } else {
      toast(txt);
    }
  });

  // ---------- 目录浏览 ----------
  //
  // 同一个弹窗两种用法：纯浏览（看路径），以及"更换共享目录"时选中一个目录。
  // 选中 = 当前所在的那一层，而不是某一行的子目录——这样"进到 D:\照片 就选它"
  // 比"必须再点一下自己"少一步，也符合文件管理器的习惯。

  var browsePath = "";
  var browsePick = null; // 非空：这次浏览是来选目录的，点确认时回调它
  var browseDrives = []; // 盘符/根列表，由服务端每次带回来，供顶部快捷条用

  var ICON_DIR = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="currentColor" fill-opacity=".28"/></svg>';

  function openBrowse(p, onPick) {
    if (onPick !== undefined) { browsePick = onPick; }
    api("/api/fs/list?path=" + encodeURIComponent(p || "")).then(function (res) {
      browsePath = res.path || "";
      if (res.drives && res.drives.length) { browseDrives = res.drives; }
      el("modal").hidden = false;
      el("modalPathInput").value = browsePath;
      renderDrives();
      var picking = !!browsePick;
      el("modalPick").hidden = !picking;
      el("modalPick").disabled = !browsePath;
      el("modalHint").textContent = picking
        ? (browsePath ? "点「共享这个目录」把共享切到：" + browsePath : "先选一个盘符或目录")
        : "只列出子目录，不列出文件名与内容。";
      var rows = [];
      if (browsePath) {
        rows.push('<div class="dir up" data-go="' + esc(parentOf(browsePath)) + '">' +
          '<span class="ic">↑</span><span class="nm">上一级</span><span class="tiny">返回</span></div>');
      }
      res.entries.forEach(function (d) {
        rows.push('<div class="dir" data-go="' + esc(d.path) + '"><span class="ic">' + ICON_DIR + "</span>" +
          '<span class="nm">' + esc(d.name) + '</span><span class="tiny">进入</span></div>');
      });
      if (!res.entries.length) {
        rows.push('<div class="empty">' + (browsePath ? "这个目录下没有子目录" : "没有可用的盘符") + "</div>");
      }
      el("modalList").innerHTML = rows.join("");
      el("modalList").scrollTop = 0;
    }).catch(function (e) {
      toast("无法浏览：" + e.message);
    });
  }

  // 顶部快捷条：一个「此电脑」加各个盘符，省得一层层退出去。
  function renderDrives() {
    var box = el("modalDrives");
    if (!box) { return; }
    var up = browsePath.toUpperCase();
    var html = ['<button class="chip' + (browsePath ? "" : " on") + '" data-go="">此电脑</button>'];
    browseDrives.forEach(function (d) {
      var on = browsePath && up.indexOf(String(d.path).toUpperCase()) === 0;
      html.push('<button class="chip' + (on ? " on" : "") + '" data-go="' + esc(d.path) + '">' + esc(d.name) + "</button>");
    });
    box.innerHTML = html.join("");
  }

  function closeModal() {
    el("modal").hidden = true;
    browsePick = null;
    el("modalPick").hidden = true;
  }

  // parentOf 算"上一级"，盘符是最容易写错的地方：
  // D:\share 的上一级是 D:\ —— 不是 D:，D: 在 Windows 里是"当前盘符的相对路径"，
  // 服务端 filepath.IsAbs 判 false 直接拒掉，表现就是"点上一级没反应、选不到别的目录"。
  // D:\ 的上一级才是"此电脑"（空串）。
  function parentOf(p) {
    var s = String(p || "").replace(/[\\/]+$/, "");
    if (!s) { return ""; }
    if (/^[A-Za-z]:$/.test(s)) { return ""; }
    var i = Math.max(s.lastIndexOf("\\"), s.lastIndexOf("/"));
    if (i < 0) { return ""; }
    var up = s.slice(0, i);
    if (/^[A-Za-z]:$/.test(up)) { return up + "\\"; }
    return up;
  }

  // 手输路径：允许只写 "D:"，补成 "D:\"；回车或点「前往」都走这里。
  function goTypedPath() {
    var v = (el("modalPathInput").value || "").trim();
    if (!v) { openBrowse(""); return; }
    if (/^[A-Za-z]:$/.test(v)) { v += "\\"; }
    openBrowse(v);
  }

  el("modalList").addEventListener("click", function (e) {
    var d = e.target.closest("[data-go]");
    if (!d) { return; }
    openBrowse(d.dataset.go);
  });

  el("modalDrives").addEventListener("click", function (e) {
    var c = e.target.closest("[data-go]");
    if (!c) { return; }
    openBrowse(c.dataset.go);
  });

  el("modalGo").addEventListener("click", goTypedPath);
  el("modalPathInput").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); goTypedPath(); }
  });

  // 共享表里的「更换目录」：带着当前根打开浏览器，确认后直接调接口。
  el("shareRows").addEventListener("click", function (e) {
    var b = e.target.closest("[data-share]");
    if (!b) { return; }
    var id = b.dataset.share;
    openBrowse(b.dataset.root, function (picked) {
      if (!picked) { toast("先进入一个目录"); return; }
      changeShareRoot(id, picked);
    });
  });

  // ---------- DLNA 设备名 ----------
  //
  // 名字就是电视/手机里显示的那一行，也是同一局域网里两台 fsgw 区分彼此的
  // 唯一线索（UUID 是随机的，用户看不见），所以放在卡片上直接改。
  function openNameModal(cur) {
    el("nameInput").value = cur || "";
    el("nameHint").textContent = "";
    el("nameModal").hidden = false;
    setTimeout(function () {
      el("nameInput").focus();
      el("nameInput").select();
    }, 30);
  }

  function closeNameModal() { el("nameModal").hidden = true; }

  function saveName() {
    var v = (el("nameInput").value || "").trim();
    if (!v) {
      el("nameHint").textContent = "名字不能为空";
      el("nameInput").focus();
      return;
    }
    var btn = el("nameSave");
    btn.disabled = true;
    el("nameHint").textContent = "保存中…";
    api("/api/dlna/name", { method: "PUT", body: JSON.stringify({ name: v }) })
      .then(function (res) {
        closeNameModal();
        banner("设备名已改为「" + res.name + "」，电视里几秒后更新。", false);
        refresh();
      })
      .catch(function (e) { el("nameHint").textContent = e.message || "保存失败"; })
      .then(function () { btn.disabled = false; });
  }

  el("svcGrid").addEventListener("click", function (e) {
    var b = e.target.closest("[data-dlna-name]");
    if (!b) { return; }
    openNameModal(b.dataset.dlnaName);
  });

  el("nameSave").addEventListener("click", saveName);
  el("nameModalClose").addEventListener("click", closeNameModal);
  el("nameModal").addEventListener("click", function (e) {
    if (e.target === el("nameModal")) { closeNameModal(); } // 点遮罩关闭
  });
  el("nameInput").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); saveName(); }
    if (e.key === "Escape") { closeNameModal(); }
  });

  el("modalPick").addEventListener("click", function () {
    var fn = browsePick;
    var p = browsePath;
    closeModal();
    if (fn) { fn(p); }
  });

  el("modalClose").addEventListener("click", closeModal);
  el("btnBrowse").addEventListener("click", function () { openBrowse("", null); });

  // 点遮罩或按 Esc 关闭；只认遮罩本身，避免点内容时误关。
  el("modal").addEventListener("click", function (e) {
    if (e.target === el("modal")) { closeModal(); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !el("modal").hidden) { closeModal(); }
  });

  // ---------- 外部访问口令 ----------

  function randomPass(n) {
    var alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    var out = "";
    var buf = new Uint8Array(n);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(buf);
    } else {
      for (var i = 0; i < n; i++) { buf[i] = Math.floor(Math.random() * 256); }
    }
    for (var j = 0; j < n; j++) { out += alphabet[buf[j] % alphabet.length]; }
    return out;
  }

  el("btnGenPass").addEventListener("click", function () {
    el("wdPass").value = randomPass(12);
    el("wdPass").focus();
  });

  el("btnSaveCred").addEventListener("click", function () {
    var user = el("wdUser").value.trim();
    var pass = el("wdPass").value;
    if (!user) { toast("请填写用户名"); return; }
    if (pass.length < 6) { toast("口令至少 6 位"); return; }

    var btn = el("btnSaveCred");
    btn.disabled = true;
    api("/api/webdav/credentials", {
      method: "PUT",
      body: JSON.stringify({ username: user, password: pass })
    }).then(function () {
      // 明文只在这一刻展示一次，方便记下来；之后服务端只存哈希。
      el("credLine").textContent = "已生效：用户名 " + user + " · 口令 " + pass + "（请自行记下）";
      el("wdPass").value = "";
      toast("已保存，新口令立即生效");
      refresh();
    }).catch(function (e) {
      toast("保存失败：" + e.message);
    }).then(function () {
      btn.disabled = false;
    });
  });

  // ---------- SMB 客户端账号 ----------

  el("btnAddSMB").addEventListener("click", function () {
    var name = el("smbName").value.trim();
    var pass = el("smbPass").value;
    var note = el("smbNote").value.trim();
    if (!name) { toast("请填写客户名"); return; }
    if (pass.length < 4) { toast("口令至少 4 位"); return; }

    var btn = el("btnAddSMB");
    btn.disabled = true;
    api("/api/smb/clients", {
      method: "POST",
      body: JSON.stringify({ name: name, password: pass, note: note })
    }).then(function () {
      el("smbPass").value = "";
      toast("已登记 " + name + "，SMB 服务已按新账号表重启");
      refresh();
    }).catch(function (e) {
      toast("登记失败：" + e.message);
    }).then(function () {
      btn.disabled = false;
    });
  });

  el("smbAcctRows").addEventListener("click", function (e) {
    var t = e.target;
    if (!t || !t.dataset || !t.dataset.smbdel) { return; }
    var name = t.dataset.smbdel;
    if (!window.confirm("移除客户端账号 " + name + "？移除后它再来会被拒绝。")) { return; }
    api("/api/smb/clients/" + encodeURIComponent(name), { method: "DELETE" })
      .then(function () {
        toast("已移除 " + name);
        refresh();
      })
      .catch(function (err) { toast("移除失败：" + err.message); });
  });

  // 点一条登录尝试 = 把那个客户名填进输入框，省得手抄（尤其名字很长时）。
  el("smbTryList").addEventListener("click", function (e) {
    var t = e.target;
    if (!t || !t.dataset || !t.dataset.smbtry) { return; }
    el("smbName").value = t.dataset.smbtry;
    el("smbPass").focus();
    toast("已填入客户名，补上口令即可");
  });

  // ---------- 审计筛选 ----------

  var auditFilter = "all";
  el("chips").addEventListener("click", function (e) {
    var b = e.target.closest(".chip");
    if (!b) { return; }
    auditFilter = b.dataset.f;
    Array.prototype.forEach.call(el("chips").children, function (c) {
      c.classList.toggle("on", c === b);
    });
    loadAudit();
  });

  function loadAudit() {
    var q = "/api/audit?limit=120";
    if (auditFilter !== "all") { q += "&filter=" + auditFilter; }
    api(q).then(renderAudit).catch(function () {});
  }

  // ---------- 轮询与事件流 ----------

  // 快同步：把地址与 token 拼成一条能直接粘进终端的命令。
  // 服务端没开（不在局域网面 / 配置关了）时给出明确原因，而不是一条会失败的命令。
  function renderSync(sy) {
    var line = el("syncLine");
    var cmd = el("syncCmd");
    if (!sy) { line.textContent = "—"; cmd.textContent = "—"; return; }
    var host = sy.addr || "";
    // 绑 0.0.0.0 时给不出可点地址，交给用户填；其余情况原样用。
    if (host.indexOf("0.0.0.0") === 0) { host = "<本机IP>" + host.slice(5); }
    if (sy.ready) {
      line.textContent = "已就绪 · " + host + " · 块 " + sy.chunk_mb + " MiB · 会话 " + sy.sessions;
      var server = "http://" + host;
      cmd.textContent = "fsgw-sync -server " + server + " -token " + sy.token +
        " -src <本地目录> -dst <目标目录>";
    } else {
      line.textContent = sy.enabled ? "未启动（需开启局域网面，见上方总开关）" : "配置中已关闭 sync.enabled";
      cmd.textContent = "—";
    }
  }

  function refresh() {
    return api("/api/status").then(render).catch(function (e) {
      if (e.message !== "unauthorized") { banner("无法获取状态：" + e.message, true); }
    });
  }

  var sseFails = 0;
  var sseSrc = null;
  var loopsStarted = false;
  var loopTimers = [];

  function connectSSE() {
    if (sseSrc) { try { sseSrc.close(); } catch (e) {} }
    // 有 token 时用查询参数（EventSource 不能设头），否则靠同源 cookie。
    var url = TOKEN ? "/api/events?token=" + encodeURIComponent(TOKEN) : "/api/events";
    var es = new EventSource(url);
    sseSrc = es;
    es.addEventListener("status", function (ev) {
      sseFails = 0;
      try { render(JSON.parse(ev.data)); } catch (e) {}
    });
    es.onerror = function () {
      // 断流后靠定时轮询兜底，不弹错误——控制台自己还在。
      try { es.close(); } catch (e) {}
      if (sseSrc === es) { sseSrc = null; }
      if (loggedOut) { return; }
      sseFails++;
      // 连错几次就探一次：网络抖动不该弹登录框，会话真没了必须弹。
      if (sseFails >= 3) {
        probeAuth().then(function (ok) {
          if (!ok) { handleUnauthorized(); return; }
          sseFails = 0;
          setTimeout(connectSSE, 2000);
        });
        return;
      }
      setTimeout(connectSSE, 4000);
    };
  }

  // probeAuth 判断当前凭据还有效吗：有 token 就验 token，否则问 whoami。
  function probeAuth() {
    if (TOKEN) {
      return tryToken(TOKEN).then(function () { return true; }, function () { return false; });
    }
    return fetch("/api/whoami", { credentials: "same-origin" }).then(function (r) {
      return r.ok;
    }, function () { return true; }); // 网络问题不算掉线
  }

  // 轮询/事件流只挂一次：登录成功、退出后重登都不该叠加定时器。
  function startLoops() {
    if (loopsStarted || loggedOut) { return; }
    loopsStarted = true;
    loadAudit();
    api("/api/diagnose").then(renderDiag).catch(function () {});
    connectSSE();
    loopTimers.push(setInterval(refresh, 5000));
    loopTimers.push(setInterval(loadAudit, 8000));
  }

  function stopLoops() {
    loopsStarted = false;
    while (loopTimers.length) { clearInterval(loopTimers.pop()); }
    if (sseSrc) { try { sseSrc.close(); } catch (e) {} sseSrc = null; }
  }

  function boot() {
    // 带 token 进来的（fsgw ui / 脚本）直接验 token，省一次 whoami。
    if (TOKEN) {
      refresh().then(function () { startLoops(); });
      return;
    }
    // 否则先问服务端"我登着吗"：cookie 有效就不弹登录框。
    fetch("/api/whoami", { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) { showGate(""); return; }
      return r.json().then(function (d) {
        setUser(d && d.user);
        afterLogin();
      });
    }).catch(function () {
      showGate("");
    });
  }

  // 右上角「退出登录」：清会话 + 清本机令牌，然后回到登录框。
  var btnToken = el("btnToken");
  if (btnToken) {
    btnToken.addEventListener("click", function () {
      fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(function () {});
      store.clear("fsgw_token");
      TOKEN = "";
      loggedOut = true;
      stopLoops();
      showGate("");
    });
  }
  var btnCopySync = el("btnCopySync");
  if (btnCopySync) {
    btnCopySync.addEventListener("click", function () {
      var txt = el("syncCmd").textContent || "";
      if (!txt || txt === "—") { return; }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function () { toast("命令已复制"); },
          function () { toast("复制失败，请手动选中"); });
      } else {
        toast("浏览器不支持自动复制，请手动选中");
      }
    });
  }
  var gateForm = el("gateForm");
  if (gateForm) {
    gateForm.addEventListener("submit", submitGate);
  }
  var gateTokenOk = el("gateTokenOk");
  if (gateTokenOk) {
    gateTokenOk.addEventListener("click", submitTokenLogin);
  }

  boot();
})();
