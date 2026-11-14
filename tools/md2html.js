#!/usr/bin/env node
/**
 * md2html — 把 docs/*.md 渲染成单页 HTML（带目录、代码高亮块、表格、callout）
 * 只支持本项目用到的 Markdown 子集，刻意不引第三方依赖。
 *
 * 用法: node tools/md2html.js
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DOCS = [
  { file: "01-技术设计说明.md", tag: "架构与实现" },
  { file: "02-数据模型与事务.md", tag: "数据与事务" },
  { file: "03-任务拆解与验收.md", tag: "施工与验收" },
  { file: "04-决策点与风险登记.md", tag: "决策与风险" },
];

let secCounter = 0;

function esc(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const MD_TO_ANCHOR = Object.fromEntries(
  DOCS.map((d, i) => [d.file, "#doc-" + d.file.slice(0, 2)])
);

function inline(text) {
  // 1. 先取出行内代码，避免后续规则污染
  const spans = [];
  let out = text.replace(/`([^`]+)`/g, (_, code) => {
    spans.push(code);
    return "\u0000C" + (spans.length - 1) + "\u0000";
  });

  out = esc(out);

  // 2. 链接
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
    let target = href;
    const base = href.split("/").pop();
    if (MD_TO_ANCHOR[base]) target = MD_TO_ANCHOR[base];
    const ext = /^https?:/.test(target) ? ' target="_blank" rel="noreferrer"' : "";
    return `<a href="${target}"${ext}>${label}</a>`;
  });

  // 3. 粗体
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");

  // 4. 还回行内代码
  out = out.replace(/\u0000C(\d+)\u0000/g, (_, i) => {
    return '<code class="inline">' + esc(spans[Number(i)]) + "</code>";
  });

  return out;
}

function isTableSep(line) {
  return /^\s*\|[\s:|-]+\|\s*$/.test(line) && line.includes("-");
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  // 处理转义竖线
  const cells = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && s[i + 1] === "|") {
      buf += "|";
      i++;
    } else if (s[i] === "|") {
      cells.push(buf.trim());
      buf = "";
    } else {
      buf += s[i];
    }
  }
  cells.push(buf.trim());
  return cells;
}

function renderDoc(doc) {
  const raw = fs.readFileSync(path.join(ROOT, "docs", doc.file), "utf8");
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  const docId = "doc-" + doc.file.slice(0, 2);

  const body = [];
  const toc = [];
  let i = 0;
  let title = doc.file;

  while (i < lines.length) {
    const line = lines[i];

    // 空行
    if (!line.trim()) {
      i++;
      continue;
    }

    // 代码块
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const buf = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        buf.push(lines[i]);
        i++;
      }
      i++;
      body.push(
        `<pre class="code" data-lang="${esc(lang)}"><code>${esc(buf.join("\n"))}</code></pre>`
      );
      continue;
    }

    // 分隔线
    if (/^---+\s*$/.test(line)) {
      body.push('<hr class="rule">');
      i++;
      continue;
    }

    // 标题
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1].length;
      const text = h[2].trim();
      if (level === 1) {
        if (body.length === 0) title = text;
        body.push(`<h2 class="doc-title" id="${docId}">${inline(text)}</h2>`);
        toc.push({ id: docId, text, level: 0 });
      } else {
        const id = "sec-" + ++secCounter;
        body.push(`<h${level} id="${id}">${inline(text)}</h${level}>`);
        toc.push({ id, text, level: Math.max(0, level - 2) });
      }
      i++;
      continue;
    }

    // 表格
    if (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      const thead = head.map((c) => `<th>${inline(c)}</th>`).join("");
      const tbody = rows
        .map((r) => "<tr>" + r.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>")
        .join("");
      body.push(
        `<div class="table-wrap"><table><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table></div>`
      );
      continue;
    }

    // 引用块 → callout
    if (line.startsWith(">")) {
      const buf = [];
      while (i < lines.length && lines[i].startsWith(">")) {
        buf.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      const text = buf.join(" ").trim();
      const warn = /风险|警告|注意|不承诺|禁止|不可/.test(text);
      const ok = /推荐|可承诺|核心|原则/.test(text);
      const cls = warn ? "warn" : ok ? "ok" : "info";
      body.push(`<div class="callout ${cls}">${inline(text)}</div>`);
      continue;
    }

    // 列表
    if (/^\s*(-|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\.\s+/.test(line);
      const items = [];
      while (i < lines.length && /^\s*(-|\d+\.)\s+/.test(lines[i])) {
        const m = /^(\s*)(-|\d+\.)\s+(.*)$/.exec(lines[i]);
        const indent = m[1].length;
        items.push({ indent, text: m[3] });
        i++;
        // 续行（缩进的普通行）
        while (
          i < lines.length &&
          lines[i].trim() &&
          /^\s{2,}/.test(lines[i]) &&
          !/^\s*(-|\d+\.)\s+/.test(lines[i]) &&
          !lines[i].includes("|")
        ) {
          items[items.length - 1].text += " " + lines[i].trim();
          i++;
        }
      }
      const tag = ordered ? "ol" : "ul";
      let html = `<${tag}>`;
      let openNested = false;
      items.forEach((it) => {
        if (it.indent >= 2 && !openNested) {
          html += "<ul class='nested'>";
          openNested = true;
        } else if (it.indent < 2 && openNested) {
          html += "</ul>";
          openNested = false;
        }
        html += `<li>${inline(it.text)}</li>`;
      });
      if (openNested) html += "</ul>";
      html += `</${tag}>`;
      body.push(html);
      continue;
    }

    // 段落（合并连续非空行）
    const para = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].startsWith("#") &&
      !lines[i].startsWith("```") &&
      !lines[i].startsWith(">") &&
      !/^\s*(-|\d+\.)\s+/.test(lines[i]) &&
      !/^---+\s*$/.test(lines[i]) &&
      !(lines[i].includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1]))
    ) {
      para.push(lines[i].trim());
      i++;
    }
    if (para.length) body.push(`<p>${inline(para.join(" "))}</p>`);
  }

  return { docId, title, tag: doc.tag, body: body.join("\n"), toc };
}

function build() {
  const rendered = DOCS.map(renderDoc);

  const tocHtml = rendered
    .map((r) => {
      const items = r.toc
        .map((t) => {
          const cls = t.level === 0 ? "toc-h2" : t.level === 1 ? "toc-h3" : "toc-h4";
          return `<a class="${cls}" href="#${t.id}">${esc(t.text)}</a>`;
        })
        .join("\n");
      return `<div class="toc-group">${items}</div>`;
    })
    .join("\n");

  const bodyHtml = rendered
    .map((r) => `<section class="card">${r.body}</section>`)
    .join("\n");

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件共享网关 · 工程设计文档</title>
<style>
  :root {
    --bg: #f7f8fa; --card: #ffffff; --text: #1f2933; --muted: #5f6b7a;
    --border: #e3e8ef; --accent: #2563eb; --accent-soft: #eff4ff;
    --warn: #b45309; --warn-soft: #fff7ed;
    --ok: #15803d; --ok-soft: #f0fdf4;
    --code-bg: #0f172a; --code-text: #e2e8f0;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
      "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
    line-height: 1.78; font-size: 15px;
  }
  .layout { display: flex; max-width: 1240px; margin: 0 auto; padding: 32px 20px 90px; gap: 30px; }
  nav.toc {
    flex: 0 0 250px; position: sticky; top: 24px; align-self: flex-start;
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px 14px; font-size: 13px; max-height: calc(100vh - 48px); overflow-y: auto;
  }
  nav.toc h3 {
    margin: 0 0 12px; font-size: 12px; color: var(--muted);
    letter-spacing: 0.06em; text-transform: uppercase;
  }
  .toc-group { margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px dashed var(--border); }
  .toc-group:last-child { border-bottom: 0; margin-bottom: 0; padding-bottom: 0; }
  nav.toc a {
    display: block; color: var(--text); text-decoration: none;
    padding: 3px 8px; border-radius: 6px; margin-bottom: 1px; line-height: 1.5;
  }
  nav.toc a:hover { background: var(--accent-soft); color: var(--accent); }
  .toc-h2 { font-weight: 600; }
  .toc-h3 { padding-left: 20px !important; color: var(--muted); font-size: 12.5px; }
  .toc-h4 { padding-left: 34px !important; color: var(--muted); font-size: 12px; }

  main { flex: 1; min-width: 0; }
  .hero {
    background: var(--card); border: 1px solid var(--border); border-radius: 14px;
    padding: 30px 32px; margin-bottom: 24px;
  }
  .hero h1 { margin: 0 0 10px; font-size: 25px; line-height: 1.35; }
  .hero p { margin: 0; color: var(--muted); font-size: 14px; }
  .tag-row { margin-top: 16px; display: flex; flex-wrap: wrap; gap: 8px; }
  .tag {
    display: inline-block; background: var(--accent-soft); color: var(--accent);
    border-radius: 999px; padding: 3px 11px; font-size: 12px; font-weight: 600;
  }
  .tag.warn { background: var(--warn-soft); color: var(--warn); }

  section.card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 14px; padding: 8px 32px 30px; margin-bottom: 22px;
  }
  h2.doc-title {
    margin: 24px 0 18px; font-size: 21px; padding-bottom: 12px;
    border-bottom: 2px solid var(--accent-soft); color: #0b1220;
  }
  h3 { margin: 30px 0 10px; font-size: 17px; color: #0b1220; padding-left: 11px; border-left: 4px solid var(--accent); }
  h2:not(.doc-title) {
    margin: 38px 0 14px; font-size: 19px; color: #0b1220;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }
  h4 { margin: 22px 0 8px; font-size: 15px; color: var(--accent); }
  p { margin: 11px 0; }
  ul, ol { margin: 11px 0; padding-left: 24px; }
  li { margin: 5px 0; }
  ul.nested { margin: 4px 0; }
  strong { color: #0b1220; }
  a { color: var(--accent); text-decoration: none; border-bottom: 1px solid #cddffd; }
  a:hover { border-bottom-color: var(--accent); }
  code.inline {
    background: #eef1f6; border-radius: 4px; padding: 1px 5px; font-size: 13px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    color: #b3306b; word-break: break-all;
  }
  pre.code {
    background: var(--code-bg); color: var(--code-text); border-radius: 10px;
    padding: 16px 18px; overflow-x: auto; font-size: 12.8px; line-height: 1.62;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    margin: 14px 0;
  }
  pre.code code { white-space: pre; }
  .table-wrap { overflow-x: auto; margin: 14px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13.8px; min-width: 520px; }
  th, td { border: 1px solid var(--border); padding: 8px 11px; text-align: left; vertical-align: top; line-height: 1.6; }
  th { background: #f3f6fb; font-weight: 600; white-space: nowrap; }
  tr:nth-child(even) td { background: #fafbfd; }
  .callout {
    border-radius: 10px; padding: 13px 16px; margin: 14px 0; font-size: 14px;
    border: 1px solid transparent; line-height: 1.7;
  }
  .callout.info { background: var(--accent-soft); border-color: #d6e2ff; }
  .callout.warn { background: var(--warn-soft); border-color: #fed7aa; }
  .callout.ok { background: var(--ok-soft); border-color: #bbf7d0; }
  hr.rule { border: 0; border-top: 1px solid var(--border); margin: 26px 0; }
  footer.doc-foot { text-align: center; color: var(--muted); font-size: 12px; padding: 12px 0 0; }
  @media (max-width: 900px) {
    .layout { flex-direction: column; padding: 16px 12px 60px; }
    nav.toc { position: static; max-height: none; }
    section.card { padding: 8px 18px 22px; }
    .hero { padding: 22px 18px; }
  }
</style>
</head>
<body>
<div class="layout">

<nav class="toc">
  <h3>目录</h3>
  ${tocHtml}
</nav>

<main>
  <div class="hero">
    <h1>文件共享网关 · 工程设计文档</h1>
    <p>局域网直读直写，外部只读走索引，SQLite 为唯一真相源。共享根 D:\\share，Windows 优先落地。</p>
    <div class="tag-row">
      <span class="tag">Go 1.22+ · CGO 关闭</span>
      <span class="tag">SQLite WAL · 单写队列</span>
      <span class="tag">移动零版本</span>
      <span class="tag">关闭即零暴露</span>
      <span class="tag warn">SMB 路线待拍板（D-01）</span>
      <span class="tag warn">快照承诺待拍板（D-02）</span>
    </div>
  </div>
${bodyHtml}
  <footer class="doc-foot">文件共享网关 · 工程设计文档 · 由 docs/*.md 生成</footer>
</main>
</div>
</body>
</html>`;
}

const outFile = path.join(ROOT, "docs", "设计文档.html");
fs.writeFileSync(outFile, build(), "utf8");
console.log("written: " + outFile);
