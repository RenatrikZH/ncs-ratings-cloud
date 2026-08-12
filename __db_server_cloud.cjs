#!/usr/bin/env node
/**
 * NCS Ratings Database Server (Cloud Edition — Turso / libSQL)
 * Depends on @libsql/client. All database operations are asynchronous.
 *
 * Features:
 *   - Turso (libSQL) database (users, ratings, comments, play_logs, messages, system_logs, login_logs)
 *   - REST API for frontend sync
 *   - 全能管理后台 at /admin (查看/删除/修改 一切数据)
 *   - 私信系统 + 系统日志 + 登录日志
 *   - CORS enabled
 *
 * Usage:  node __db_server_cloud.cjs
 * Env:    TURSO_URL, TURSO_TOKEN, PORT
 */

// 使用 HTTP 模式，避免依赖平台特定的原生二进制模块（@libsql/linux-x64-gnu 等）
// HTTP 模式通过 Turso 的 HTTP API 连接，在 Netlify/Vercel 等 Serverless 环境中更稳定
const { createClient } = require('@libsql/client/http');
const http = require('node:http');
const crypto = require('node:crypto');
const url = require('node:url');
const path = require('node:path');
const fs = require('node:fs');

// ============ CONFIG ============
const PORT = process.env.PORT || 3000;
const TURSO_URL = process.env.TURSO_URL || 'libsql://localhost:8080';
const TURSO_TOKEN = process.env.TURSO_TOKEN;
const SALT = 'ncs_ratings_salt_2024';

// ============ DATABASE INIT ============
const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// 建表 / 建索引 — Turso 不支持 PRAGMA journal_mode=WAL，已去掉
const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    avatar TEXT,
    phone TEXT,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  );

  CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    audio_url TEXT NOT NULL,
    vote INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(username, audio_url)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    audio_url TEXT NOT NULL,
    vote INTEGER DEFAULT 0,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS play_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    audio_url TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    played_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    text TEXT NOT NULL,
    read_flag INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT DEFAULT 'INFO',
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    success INTEGER DEFAULT 0,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    attachment_data TEXT,
    attachment_name TEXT,
    attachment_type TEXT,
    admin_reply TEXT,
    replied_at TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS community_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    attachment_data TEXT,
    attachment_name TEXT,
    attachment_type TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_ratings_audio ON ratings(audio_url);
  CREATE INDEX IF NOT EXISTS idx_comments_audio ON comments(audio_url);
  CREATE INDEX IF NOT EXISTS idx_playlogs_audio ON play_logs(audio_url);
  CREATE INDEX IF NOT EXISTS idx_ratings_user ON ratings(username);
  CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(username);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
  CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver);
  CREATE INDEX IF NOT EXISTS idx_loginlogs_user ON login_logs(username);
  CREATE INDEX IF NOT EXISTS idx_syslogs_action ON system_logs(action);
  CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(username);
  CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
  CREATE INDEX IF NOT EXISTS idx_community_created ON community_posts(created_at);
`;

// ============ SCHEMA MIGRATION (为旧库添加新列) ============
// ALTER TABLE ADD COLUMN 在列已存在时会报错，用 try/catch 忽略
async function addColumnIfMissing(table, column, def) {
  try { await db.execute(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`); }
  catch (e) { /* 列已存在，忽略 */ }
}

async function initDB() {
  await db.executeMultiple(SCHEMA_SQL);
  await addColumnIfMissing('users', 'phone', 'TEXT');
  await addColumnIfMissing('users', 'email', 'TEXT');
  await addColumnIfMissing('users', 'role', "TEXT DEFAULT 'user'");
  await addColumnIfMissing('users', 'banned', 'INTEGER DEFAULT 0');
  await addColumnIfMissing('users', 'last_login', 'TEXT');
  await addColumnIfMissing('play_logs', 'ip', 'TEXT');
  await addColumnIfMissing('play_logs', 'user_agent', 'TEXT');
}

// ============ HELPERS ============
function hashPwd(pwd) {
  return crypto.createHash('sha256').update(pwd + SALT).digest('hex');
}

// ============ 图形验证码系统（无状态签名，兼容 Serverless） ============
// 使用 HMAC-SHA256 签名令牌，无需内存存储，适配 Netlify/Vercel 等 Serverless 环境
const CAPTCHA_SECRET = SALT + '_captcha_v1';
const CAPTCHA_EXPIRE = 5 * 60 * 1000; // 5分钟有效期

function generateCaptcha() {
  // 生成4位验证码（排除易混字符 I O 0 1）
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 4; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  // 无状态令牌：base64(code:timestamp).hmac签名
  const ts = Date.now();
  const payload = Buffer.from(code + ':' + ts).toString('base64');
  const sig = crypto.createHmac('sha256', CAPTCHA_SECRET).update(payload).digest('hex');
  return { token: payload + '.' + sig, code };
}
// 生成 SVG 验证码图片（纯文本，无需 Canvas/canvas 库）
function generateCaptchaSVG(code) {
  const colors = ['#22c55e', '#3b82f6', '#a855f7', '#f59e0b', '#ef4444', '#06b6d4'];
  // 干扰线
  let lines = '';
  for (let i = 0; i < 6; i++) {
    const x1 = Math.random() * 160, y1 = Math.random() * 50;
    const x2 = Math.random() * 160, y2 = Math.random() * 50;
    const lc = colors[Math.floor(Math.random() * colors.length)];
    lines += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${lc}" stroke-width="1" opacity="0.3"/>`;
  }
  // 干扰点
  let dots = '';
  for (let i = 0; i < 30; i++) {
    dots += `<circle cx="${Math.random() * 160}" cy="${Math.random() * 50}" r="1" fill="${colors[Math.floor(Math.random() * colors.length)]}" opacity="0.4"/>`;
  }
  // 每个字符随机旋转、偏移
  let text = '';
  for (let i = 0; i < code.length; i++) {
    const x = 20 + i * 35;
    const y = 35 + (Math.random() - 0.5) * 10;
    const rot = (Math.random() - 0.5) * 30;
    const color = colors[Math.floor(Math.random() * colors.length)];
    text += `<text x="${x}" y="${y}" font-size="28" font-family="monospace" font-weight="bold" fill="${color}" transform="rotate(${rot} ${x} ${y})">${code[i]}</text>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="50" viewBox="0 0 160 50">
    <rect width="160" height="50" fill="#1a1a20" rx="8"/>
    ${lines}${dots}${text}
  </svg>`;
}
function verifyCaptcha(token, input) {
  if (!token || !input) return false;
  try {
    const parts = String(token).split('.');
    if (parts.length !== 2) return false;
    const [payload, sig] = parts;
    // 验证签名
    const expectedSig = crypto.createHmac('sha256', CAPTCHA_SECRET).update(payload).digest('hex');
    if (sig !== expectedSig) return false;
    // 解码 payload
    const decoded = Buffer.from(payload, 'base64').toString('utf8');
    const colonIdx = decoded.lastIndexOf(':');
    if (colonIdx < 1) return false;
    const code = decoded.slice(0, colonIdx);
    const ts = parseInt(decoded.slice(colonIdx + 1), 10);
    // 检查过期
    if (isNaN(ts) || Date.now() - ts > CAPTCHA_EXPIRE) return false;
    // 比对验证码（不区分大小写）
    return code === String(input).toUpperCase();
  } catch (e) {
    return false;
  }
}

// ============ 邮箱验证码系统（无状态签名，兼容 Serverless） ============
// 验证码通过 HMAC-SHA256 签名令牌验证，无需内存存储
// 支持多种邮箱 SMTP 发送：QQ邮箱 / 163 / 126 / 139 / 新浪 / Gmail / Outlook / Resend
// QQ邮箱（优先推荐，完全免费）：
//   1. QQ邮箱网页版 → 设置 → 账户 → 开启 SMTP 服务
//   2. 生成"授权码"（非邮箱密码）
//   3. 设置环境变量：QQ_EMAIL=xxx@qq.com  QQ_AUTH_CODE=授权码
const EMAIL_CODE_SECRET = SALT + '_email_code_v1';
const EMAIL_CODE_EXPIRE = 5 * 60 * 1000; // 5分钟有效期

// 支持的邮箱服务商 SMTP 配置（全部免费，用户只需配置对应授权码）
const EMAIL_PROVIDERS = [
  { name: 'QQ邮箱',  check: (u)=>/\@qq\.com$/i.test(u), host:'smtp.qq.com',       port:465, secure:true, userEnv:'QQ_EMAIL',     passEnv:'QQ_AUTH_CODE'  },
  { name: 'QQ企业邮箱', check:(u)=>/\.qq\.com$/i.test(u) && !/\@qq\.com$/i.test(u), host:'smtp.exmail.qq.com', port:465, secure:true, userEnv:'QQ_EXMAIL_USER', passEnv:'QQ_EXMAIL_PASS' },
  { name: '163邮箱', check: (u)=>/\@163\.com$/i.test(u), host:'smtp.163.com',      port:465, secure:true, userEnv:'EMAIL_163',    passEnv:'PASS_163'      },
  { name: '126邮箱', check: (u)=>/\@126\.com$/i.test(u), host:'smtp.126.com',      port:465, secure:true, userEnv:'EMAIL_126',    passEnv:'PASS_126'      },
  { name: '139邮箱', check: (u)=>/\@139\.com$/i.test(u), host:'smtp.139.com',      port:465, secure:true, userEnv:'EMAIL_139',    passEnv:'PASS_139'      },
  { name: '新浪邮箱', check: (u)=>/\@sina\.(com|cn)$/i.test(u), host:'smtp.sina.com', port:465, secure:true, userEnv:'EMAIL_SINA',   passEnv:'PASS_SINA'     },
  { name: 'Outlook', check: (u)=>/\@(outlook|hotmail|live)\.com$/i.test(u), host:'smtp-mail.outlook.com', port:587, secure:false, starttls:true, userEnv:'EMAIL_OUTLOOK', passEnv:'PASS_OUTLOOK' },
  { name: 'Gmail',   check: (u)=>/\@gmail\.com$/i.test(u), host:'smtp.gmail.com',    port:465, secure:true, userEnv:'EMAIL_GMAIL',   passEnv:'PASS_GMAIL'    },
  { name: 'Foxmail', check: (u)=>/\@foxmail\.com$/i.test(u), host:'smtp.qq.com',      port:465, secure:true, userEnv:'FOXMAIL_USER',  passEnv:'FOXMAIL_PASS'  },
];

// 通用自定义 SMTP（用于其他邮箱）
const CUSTOM_SMTP = {
  host: process.env.SMTP_HOST || '',
  port: parseInt(process.env.SMTP_PORT || '465', 10),
  secure: String(process.env.SMTP_SECURE || 'true') === 'true',
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  from: process.env.SMTP_FROM || ''
};

// 根据收件人匹配邮箱服务商，返回 SMTP 配置
function resolveSmtpConfig(toEmail) {
  // 1. 优先：自定义通用 SMTP（若配置了 user+pass+host）
  if (CUSTOM_SMTP.host && CUSTOM_SMTP.user && CUSTOM_SMTP.pass) {
    return {
      name: '自定义SMTP',
      host: CUSTOM_SMTP.host,
      port: CUSTOM_SMTP.port,
      secure: CUSTOM_SMTP.secure,
      auth: { user: CUSTOM_SMTP.user, pass: CUSTOM_SMTP.pass },
      from: CUSTOM_SMTP.from || CUSTOM_SMTP.user
    };
  }
  // 2. 匹配收件邮箱对应服务商（用户在对应环境变量配置了账号+授权码）
  for (const p of EMAIL_PROVIDERS) {
    if (p.check(toEmail)) {
      const user = process.env[p.userEnv] || '';
      const pass = process.env[p.passEnv] || '';
      if (user && pass) {
        return {
          name: p.name,
          host: p.host,
          port: p.port,
          secure: p.secure,
          starttls: p.starttls || false,
          auth: { user, pass },
          from: `NCS Ratings <${user}>`
        };
      }
    }
  }
  // 3. Resend API（付费方案，需配置 API_KEY）
  const resendKey = process.env.RESEND_API_KEY || '';
  if (resendKey) {
    return { name: 'Resend', resendKey };
  }
  return null; // 无可用配置，走开发模式
}

function generateEmailCode() {
  let code = '';
  for (let i = 0; i < 6; i++) code += Math.floor(Math.random() * 10);
  const ts = Date.now();
  const payload = Buffer.from(code + ':' + ts).toString('base64');
  const sig = crypto.createHmac('sha256', EMAIL_CODE_SECRET).update(payload).digest('hex');
  return { token: payload + '.' + sig, code };
}

function verifyEmailCode(token, input) {
  if (!token || !input) return false;
  try {
    const parts = String(token).split('.');
    if (parts.length !== 2) return false;
    const [payload, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', EMAIL_CODE_SECRET).update(payload).digest('hex');
    if (sig !== expectedSig) return false;
    const decoded = Buffer.from(payload, 'base64').toString('utf8');
    const colonIdx = decoded.lastIndexOf(':');
    if (colonIdx < 1) return false;
    const code = decoded.slice(0, colonIdx);
    const ts = parseInt(decoded.slice(colonIdx + 1), 10);
    if (isNaN(ts) || Date.now() - ts > EMAIL_CODE_EXPIRE) return false;
    return code === String(input);
  } catch (e) {
    return false;
  }
}

// 发送邮件：支持 nodemailer(SMTP) / Resend(HTTP API) / dev_mode
let _mailerCache = null; // nodemailer transporter 缓存
async function sendEmail(to, subject, htmlContent) {
  const cfg = resolveSmtpConfig(to);

  // 方案 A：Resend API（HTTP 调用）
  if (cfg && cfg.resendKey) {
    try {
      const https = require('node:https');
      const data = JSON.stringify({
        from: `NCS Ratings <noreply@resend.dev>`,
        to: [to],
        subject,
        html: htmlContent
      });
      return await new Promise((resolve) => {
        const req = https.request('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + cfg.resendKey, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, (resp) => {
          let body = '';
          resp.on('data', chunk => body += chunk);
          resp.on('end', () => resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, provider: 'Resend', status: resp.statusCode, body: body.substring(0,200) }));
        });
        req.on('error', err => resolve({ ok: false, provider: 'Resend', error: String(err).substring(0,200) }));
        req.write(data);
        req.end();
      });
    } catch (e) {
      return { ok: false, provider: 'Resend', error: String(e).substring(0,200) };
    }
  }

  // 方案 B：SMTP 真实发送（QQ邮箱/163/126等，nodemailer）
  if (cfg && cfg.host) {
    try {
      const nodemailer = require('nodemailer');
      // 不同服务复用 transporter
      const cacheKey = cfg.auth.user + '|' + cfg.host + ':' + cfg.port;
      if (!_mailerCache || _mailerCache.key !== cacheKey) {
        const opts = {
          host: cfg.host,
          port: cfg.port,
          secure: !!cfg.secure,
          auth: { user: cfg.auth.user, pass: cfg.auth.pass },
          connectionTimeout: 15000,
          greetingTimeout: 15000,
          socketTimeout: 15000
        };
        if (cfg.starttls) {
          opts.secure = false;
          opts.requireTLS = true;
          opts.tls = { ciphers: 'SSLv3' };
        }
        _mailerCache = { key: cacheKey, transporter: nodemailer.createTransport(opts) };
      }
      const info = await _mailerCache.transporter.sendMail({
        from: cfg.from || cfg.auth.user,
        to,
        subject,
        html: htmlContent
      });
      return { ok: !!info.messageId, provider: cfg.name, messageId: info.messageId, response: String(info.response || '').substring(0,200) };
    } catch (e) {
      // SMTP 发送失败时，不降级到开发模式，让用户知道原因
      return { ok: false, provider: cfg.name, error: String(e).substring(0, 300), dev_mode: true, dev_reason: 'SMTP失败: ' + String(e).substring(0,80) };
    }
  }

  // 方案 C：未配置任何邮件服务 → 开发模式（验证码通过接口返回给前端toast显示）
  return { ok: true, dev_mode: true, provider: 'DevMode', hint: '未配置邮件服务，验证码将显示在页面' };
}

// 获取上海时区的日期字符串 YYYY-MM-DD
function getShanghaiDate() {
  const now = new Date();
  // UTC + 8 小时 = 上海时间
  const shanghai = new Date(now.getTime() + 8 * 60 * 60 * 1000);
  const y = shanghai.getUTCFullYear();
  const m = String(shanghai.getUTCMonth() + 1).padStart(2, '0');
  const d = String(shanghai.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function sendJSON(res, data, status) {
  status = status || 200;
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise(function (resolve) {
    let body = '';
    req.on('data', function (c) {
      body += c;
      if (body.length > 2e6) { resolve({}); req.destroy(); }
    });
    req.on('end', function () {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (e) { resolve({}); }
    });
  });
}

function getIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket.remoteAddress || '-';
}

function getUA(req) {
  return (req.headers['user-agent'] || '').slice(0, 200);
}

// 系统日志记录（永不抛错，避免影响主流程）— 异步，调用方可不 await
async function logSystem(level, action, target, detail, ip) {
  try {
    await db.execute({
      sql: 'INSERT INTO system_logs (level, action, target, detail, ip) VALUES (?, ?, ?, ?, ?)',
      args: [level || 'INFO', action || '', target || '', String(detail || '').slice(0, 500), ip || '']
    });
  } catch (e) {}
}

// 登录日志记录 — 异步，调用方可不 await
async function logLogin(username, success, ip, ua) {
  try {
    await db.execute({
      sql: 'INSERT INTO login_logs (username, success, ip, user_agent) VALUES (?, ?, ?, ?)',
      args: [username || '', success ? 1 : 0, ip || '', (ua || '').slice(0, 200)]
    });
  } catch (e) {}
}

async function getRatingsForSong(audioUrl) {
  const result = await db.execute({
    sql: 'SELECT username, vote FROM ratings WHERE audio_url = ? AND vote != 0',
    args: [audioUrl]
  });
  const out = { likes: 0, dislikes: 0, users: {} };
  for (const r of result.rows) {
    if (r.vote === 1) out.likes++;
    else if (r.vote === -1) out.dislikes++;
    out.users[r.username] = r.vote;
  }
  return out;
}

function shortUrl(u) {
  if (!u) return '-';
  try { return decodeURIComponent(u.split('/').pop() || u).slice(0, 60); }
  catch (e) { return u.slice(0, 60); }
}

// ============ API HANDLERS ============

async function apiHealth(req, res) {
  sendJSON(res, { ok: true, time: new Date().toISOString(), db: TURSO_URL });
}

// 公开接口：返回今日日期
async function apiDailyInfo(req, res) {
  const date = getShanghaiDate();
  sendJSON(res, { date, hint: '注册/登录时请输入邮箱接收验证码' });
}

// 生成图形验证码（返回 SVG 图片 + 签名令牌）— 保留用于管理后台等场景
async function apiCaptcha(req, res) {
  const { token, code } = generateCaptcha();
  const svg = generateCaptchaSVG(code);
  sendJSON(res, { id: token, svg });
}

// 发送邮箱验证码（注册/登录通用）
async function apiSendCode(req, res) {
  const { email, purpose } = await readBody(req);
  const ip = getIP(req);
  if (!email) return sendJSON(res, { error: '请输入邮箱地址' }, 400);
  // 简单邮箱格式校验
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendJSON(res, { error: '邮箱格式不正确' }, 400);
  }
  // 如果是登录，检查邮箱是否已注册
  if (purpose === 'login') {
    const result = await db.execute({ sql: 'SELECT username FROM users WHERE email = ?', args: [email] });
    if (!result.rows[0]) {
      return sendJSON(res, { error: '该邮箱未注册，请先注册' }, 404);
    }
  }
  // 如果是注册，检查邮箱是否已被使用
  if (purpose === 'register') {
    const result = await db.execute({ sql: 'SELECT username FROM users WHERE email = ?', args: [email] });
    if (result.rows[0]) {
      return sendJSON(res, { error: '该邮箱已注册，请直接登录' }, 409);
    }
  }
  // 生成验证码
  const { token, code } = generateEmailCode();
  const subject = purpose === 'login' ? '【NCS Ratings】登录验证码' : '【NCS Ratings】注册验证码';
  const html = `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px">
    <h2 style="color:#6366f1">🎵 NCS Ratings</h2>
    <p>您的验证码是：</p>
    <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#6366f1;background:#f3f4f6;padding:16px;border-radius:8px;text-align:center;margin:16px 0">${code}</div>
    <p style="color:#6b7280;font-size:13px">验证码5分钟内有效，请勿泄露给他人。</p>
  </div>`;
  const emailResult = await sendEmail(email, subject, html);
  logSystem('INFO', 'SEND_CODE_RESULT', email, JSON.stringify(emailResult).substring(0,300), ip);

  const resp = { success: false, token };
  if (emailResult.ok) {
    resp.success = true;
    resp.provider = emailResult.provider || 'DevMode';
    if (emailResult.dev_mode) {
      resp.dev_code = code;
      resp.dev_mode = true;
      if (emailResult.hint) resp.hint = emailResult.hint;
    } else {
      resp.hint = '验证码已发送至 ' + email + '，请注意查收邮件';
    }
    sendJSON(res, resp);
    return;
  }
  // SMTP发送失败 → 降级为开发模式显示验证码（避免完全不可用），并告知失败原因
  resp.success = true; // 降级后仍认为成功，验证码可以用
  resp.provider = 'DevMode(Fallback)';
  resp.dev_code = code;
  resp.dev_mode = true;
  resp.fallback_reason = '邮件服务异常(' + (emailResult.provider || 'unknown') + '): ' + (emailResult.error || emailResult.dev_reason || '').substring(0,60);
  resp.hint = '邮件发送失败，当前使用备用模式，已显示验证码';
  logSystem('WARN', 'SEND_CODE_FALLBACK', email, resp.fallback_reason, ip);
  sendJSON(res, resp);
}

async function apiRegister(req, res) {
  const { username, email, codeToken, code } = await readBody(req);
  const ip = getIP(req);
  if (!username) return sendJSON(res, { error: '请输入用户名' }, 400);
  if (!email) return sendJSON(res, { error: '请输入邮箱' }, 400);
  if (!code) return sendJSON(res, { error: '请输入验证码' }, 400);
  if (username.length < 2) return sendJSON(res, { error: '用户名至少2个字符' }, 400);
  // 验证邮箱验证码
  if (!verifyEmailCode(codeToken, code)) {
    logSystem('WARN', 'REGISTER_CODE_FAIL', username, '验证码错误或已过期', ip);
    return sendJSON(res, { error: '验证码错误或已过期，请重新获取' }, 403);
  }
  try {
    await db.execute({
      sql: 'INSERT INTO users (username, password_hash, email, phone) VALUES (?, ?, ?, ?)',
      args: [username, hashPwd(email + '_' + Date.now()), email, '']
    });
    logSystem('INFO', 'REGISTER', username, '新用户注册（邮箱验证码验证通过）邮箱:' + email, ip);
    sendJSON(res, { success: true, user: { name: username, email: email, joined: new Date().toISOString() } });
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      logSystem('WARN', 'REGISTER_DUPLICATE', username, '尝试注册已存在用户名', ip);
      sendJSON(res, { error: '用户名已存在' }, 409);
    }
    else sendJSON(res, { error: '注册失败: ' + (e.message || e) }, 500);
  }
}

async function apiLogin(req, res) {
  const { email, codeToken, code } = await readBody(req);
  const ip = getIP(req);
  const ua = getUA(req);
  if (!email || !code) return sendJSON(res, { error: '请输入邮箱和验证码' }, 400);
  // 验证邮箱验证码
  if (!verifyEmailCode(codeToken, code)) {
    logLogin(email, 0, ip, ua);
    logSystem('WARN', 'LOGIN_CODE_FAIL', email, '验证码错误或已过期', ip);
    return sendJSON(res, { error: '验证码错误或已过期，请重新获取' }, 403);
  }
  // 查找用户
  const loginResult = await db.execute({
    sql: 'SELECT username, email, created_at, banned FROM users WHERE email = ?',
    args: [email]
  });
  const row = loginResult.rows[0];
  if (!row) {
    logLogin(email, 0, ip, ua);
    logSystem('WARN', 'LOGIN_FAIL', email, '登录失败（邮箱未注册）', ip);
    return sendJSON(res, { error: '该邮箱未注册，请先注册' }, 401);
  }
  if (row.banned) {
    logLogin(row.username, 0, ip, ua);
    logSystem('WARN', 'LOGIN_BANNED', row.username, '被封禁用户尝试登录', ip);
    return sendJSON(res, { error: '账号已被封禁，请联系管理员' }, 403);
  }
  await db.execute({
    sql: "UPDATE users SET last_login = datetime('now') WHERE email = ?",
    args: [email]
  });
  logLogin(row.username, 1, ip, ua);
  logSystem('INFO', 'LOGIN', row.username, '登录成功（邮箱验证码）', ip);
  sendJSON(res, { success: true, user: { name: row.username, email: row.email, joined: row.created_at } });
}

async function apiRate(req, res) {
  const { username, audioUrl, vote } = await readBody(req);
  if (!username || !audioUrl) return sendJSON(res, { error: '参数缺失' }, 400);
  if (vote === 0) {
    await db.execute({
      sql: 'DELETE FROM ratings WHERE username = ? AND audio_url = ?',
      args: [username, audioUrl]
    });
  } else {
    await db.execute({
      sql: 'INSERT INTO ratings (username, audio_url, vote) VALUES (?, ?, ?) ON CONFLICT(username, audio_url) DO UPDATE SET vote = excluded.vote',
      args: [username, audioUrl, vote]
    });
  }
  sendJSON(res, { success: true, ratings: await getRatingsForSong(audioUrl) });
}

async function apiComment(req, res) {
  const { username, audioUrl, vote, text } = await readBody(req);
  if (!username || !audioUrl || !text) return sendJSON(res, { error: '参数缺失' }, 400);
  await db.execute({
    sql: 'INSERT INTO comments (username, audio_url, vote, text) VALUES (?, ?, ?, ?)',
    args: [username, audioUrl, vote || 0, text]
  });
  sendJSON(res, { success: true });
}

async function apiPlay(req, res) {
  const { username, audioUrl } = await readBody(req);
  if (!audioUrl) return sendJSON(res, { error: '参数缺失' }, 400);
  await db.execute({
    sql: 'INSERT INTO play_logs (username, audio_url, ip, user_agent) VALUES (?, ?, ?, ?)',
    args: [username || 'anonymous', audioUrl, getIP(req), getUA(req)]
  });
  sendJSON(res, { success: true });
}

// 私信：发送
async function apiSendMessage(req, res) {
  const { sender, receiver, text } = await readBody(req);
  if (!sender || !receiver || !text) return sendJSON(res, { error: '参数缺失' }, 400);
  if (sender === receiver) return sendJSON(res, { error: '不能给自己发私信' }, 400);
  // 验证收件人存在
  const recvResult = await db.execute({
    sql: 'SELECT username FROM users WHERE username = ?',
    args: [receiver]
  });
  if (!recvResult.rows[0]) return sendJSON(res, { error: '收件人不存在' }, 404);
  await db.execute({
    sql: 'INSERT INTO messages (sender, receiver, text) VALUES (?, ?, ?)',
    args: [sender, receiver, text]
  });
  logSystem('INFO', 'MESSAGE_SEND', sender, '发给 ' + receiver, getIP(req));
  sendJSON(res, { success: true });
}

// 私信：获取某用户的所有私信
async function apiGetMessages(req, res) {
  const q = url.parse(req.url, true).query;
  const username = q.username;
  if (!username) return sendJSON(res, { error: 'username required' }, 400);
  const result = await db.execute({
    sql: 'SELECT id, sender, receiver, text, read_flag, created_at FROM messages WHERE sender = ? OR receiver = ? ORDER BY created_at DESC LIMIT 500',
    args: [username, username]
  });
  sendJSON(res, result.rows);
}

async function apiGetAll(req, res) {
  const ratingResult = await db.execute({
    sql: 'SELECT audio_url, username, vote FROM ratings WHERE vote != 0'
  });
  const ratings = {};
  for (const r of ratingResult.rows) {
    if (!ratings[r.audio_url]) ratings[r.audio_url] = { likes: 0, dislikes: 0, users: {} };
    if (r.vote === 1) ratings[r.audio_url].likes++;
    else if (r.vote === -1) ratings[r.audio_url].dislikes++;
    ratings[r.audio_url].users[r.username] = r.vote;
  }
  const commentResult = await db.execute({
    sql: 'SELECT audio_url, username, vote, text, created_at FROM comments ORDER BY created_at'
  });
  const comments = {};
  for (const c of commentResult.rows) {
    if (!comments[c.audio_url]) comments[c.audio_url] = [];
    comments[c.audio_url].push({ user: c.username, vote: c.vote, text: c.text, time: c.created_at });
  }
  const userResult = await db.execute({
    sql: 'SELECT username, avatar, created_at FROM users'
  });
  const users = {};
  for (const u of userResult.rows) {
    users[u.username] = { joined: u.created_at };
    if (u.avatar) users[u.username].avatar = u.avatar;
  }
  sendJSON(res, { ratings, comments, users });
}

async function apiGetSong(req, res) {
  const q = url.parse(req.url, true).query;
  const audioUrl = q.audioUrl;
  if (!audioUrl) return sendJSON(res, { error: 'audioUrl required' }, 400);
  const ratings = await getRatingsForSong(audioUrl);
  const commentResult = await db.execute({
    sql: 'SELECT username, vote, text, created_at FROM comments WHERE audio_url = ? ORDER BY created_at',
    args: [audioUrl]
  });
  const comments = commentResult.rows.map(function (c) {
    return { user: c.username, vote: c.vote, text: c.text, time: c.created_at };
  });
  sendJSON(res, { ratings, comments });
}

async function apiStats(req, res) {
  const totalUsers = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM users' })).rows[0].c;
  const totalRatings = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM ratings WHERE vote != 0' })).rows[0].c;
  const totalComments = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM comments' })).rows[0].c;
  const totalPlays = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM play_logs' })).rows[0].c;
  const likes = (await db.execute({ sql: "SELECT COUNT(*) as c FROM ratings WHERE vote = 1" })).rows[0].c;
  const dislikes = (await db.execute({ sql: "SELECT COUNT(*) as c FROM ratings WHERE vote = -1" })).rows[0].c;
  const topSongs = (await db.execute({
    sql: `SELECT audio_url,
           SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END) as likes,
           SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END) as dislikes,
           COUNT(*) as total
    FROM ratings WHERE vote != 0
    GROUP BY audio_url ORDER BY total DESC LIMIT 10`
  })).rows;
  const recent = (await db.execute({
    sql: `SELECT '评分' as type, username, audio_url, vote as extra, created_at as time FROM ratings WHERE vote != 0
    UNION ALL
    SELECT '评论' as type, username, audio_url, NULL as extra, created_at as time FROM comments
    ORDER BY time DESC LIMIT 30`
  })).rows;
  sendJSON(res, { totalUsers, totalRatings, totalComments, totalPlays, likes, dislikes, topSongs, recent });
}

async function apiSync(req, res) {
  const { ratings, comments, users } = await readBody(req);
  let imported = { ratings: 0, comments: 0, users: 0 };
  try {
    if (users) {
      for (const name of Object.keys(users)) {
        const data = users[name];
        if (!name) continue;
        try {
          await db.execute({
            sql: 'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
            args: [name, hashPwd(data.pass || 'migrated')]
          });
          imported.users++;
        } catch (e) {}
      }
    }
    if (ratings) {
      for (const audioUrl of Object.keys(ratings)) {
        const data = ratings[audioUrl];
        if (!data || !data.users) continue;
        for (const username of Object.keys(data.users)) {
          const vote = data.users[username];
          if (!vote) continue;
          try {
            await db.execute({
              sql: 'INSERT INTO ratings (username, audio_url, vote) VALUES (?, ?, ?) ON CONFLICT(username, audio_url) DO UPDATE SET vote = excluded.vote',
              args: [username, audioUrl, vote]
            });
            imported.ratings++;
          } catch (e) {}
        }
      }
    }
    if (comments) {
      for (const audioUrl of Object.keys(comments)) {
        const arr = comments[audioUrl];
        if (!Array.isArray(arr)) continue;
        for (const c of arr) {
          if (!c.user || !c.text) continue;
          try {
            await db.execute({
              sql: 'INSERT INTO comments (username, audio_url, vote, text) VALUES (?, ?, ?, ?)',
              args: [c.user, audioUrl, c.vote || 0, c.text]
            });
            imported.comments++;
          } catch (e) {}
        }
      }
    }
    sendJSON(res, { success: true, imported });
  } catch (e) {
    sendJSON(res, { error: 'Sync failed: ' + e.message }, 500);
  }
}

// ============ 反馈系统 API ============
// 用户提交反馈（支持图片/文件 base64 附件，限制 500KB）
async function apiSubmitFeedback(req, res) {
  const { username, message, attachmentData, attachmentName, attachmentType } = await readBody(req);
  const ip = getIP(req);
  if (!username || !message) return sendJSON(res, { error: '用户名和反馈内容不能为空' }, 400);
  if (message.length > 1000) return sendJSON(res, { error: '反馈内容不能超过1000字' }, 400);
  // 限制附件大小 500KB（base64 约 670KB）
  if (attachmentData && attachmentData.length > 700000) {
    return sendJSON(res, { error: '附件过大，请限制在500KB以内' }, 400);
  }
  try {
    await db.execute({
      sql: 'INSERT INTO feedback (username, message, attachment_data, attachment_name, attachment_type, ip) VALUES (?, ?, ?, ?, ?, ?)',
      args: [username, message, attachmentData || null, attachmentName || null, attachmentType || null, ip]
    });
    logSystem('INFO', 'FEEDBACK_SUBMIT', username, '用户提交反馈', ip);
    sendJSON(res, { success: true, message: '反馈已提交，管理员会尽快回复' });
  } catch (e) {
    sendJSON(res, { error: '提交失败: ' + e.message }, 500);
  }
}

// 用户查看自己的反馈及管理员回复
async function apiGetFeedback(req, res) {
  const parsed = url.parse(req.url, true);
  const username = parsed.query.username;
  if (!username) return sendJSON(res, { error: '缺少用户名参数' }, 400);
  const result = await db.execute({
    sql: 'SELECT id, message, attachment_data, attachment_name, attachment_type, admin_reply, replied_at, created_at FROM feedback WHERE username = ? ORDER BY created_at DESC LIMIT 100',
    args: [username]
  });
  sendJSON(res, result.rows);
}

// ============ 社区模块 API ============
// 用户发帖（内容不超过300字，支持图片/文件附件）
async function apiCommunityPost(req, res) {
  const { username, content, attachmentData, attachmentName, attachmentType } = await readBody(req);
  const ip = getIP(req);
  if (!username || !content) return sendJSON(res, { error: '用户名和内容不能为空' }, 400);
  if (content.length > 300) return sendJSON(res, { error: '内容不能超过300字' }, 400);
  if (attachmentData && attachmentData.length > 700000) {
    return sendJSON(res, { error: '附件过大，请限制在500KB以内' }, 400);
  }
  try {
    await db.execute({
      sql: 'INSERT INTO community_posts (username, content, attachment_data, attachment_name, attachment_type, ip) VALUES (?, ?, ?, ?, ?, ?)',
      args: [username, content, attachmentData || null, attachmentName || null, attachmentType || null, ip]
    });
    sendJSON(res, { success: true, message: '发布成功' });
  } catch (e) {
    sendJSON(res, { error: '发布失败: ' + e.message }, 500);
  }
}

// 获取社区帖子列表（显示一年内的信息）
async function apiCommunityList(req, res) {
  const result = await db.execute({
    sql: `SELECT id, username, content, attachment_data, attachment_name, attachment_type, created_at
          FROM community_posts
          WHERE created_at >= datetime('now', '-1 year')
          ORDER BY created_at DESC
          LIMIT 500`
  });
  sendJSON(res, result.rows);
}

// ============ ADMIN HANDLERS ============

async function adminOverview(req, res) {
  const totalUsers = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM users' })).rows[0].c;
  const totalRatings = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM ratings WHERE vote != 0' })).rows[0].c;
  const totalComments = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM comments' })).rows[0].c;
  const totalPlays = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM play_logs' })).rows[0].c;
  const totalMessages = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM messages' })).rows[0].c;
  const totalLogs = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM system_logs' })).rows[0].c;
  const totalLoginLogs = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM login_logs' })).rows[0].c;
  const likes = (await db.execute({ sql: "SELECT COUNT(*) as c FROM ratings WHERE vote = 1" })).rows[0].c;
  const dislikes = (await db.execute({ sql: "SELECT COUNT(*) as c FROM ratings WHERE vote = -1" })).rows[0].c;
  const bannedUsers = (await db.execute({ sql: "SELECT COUNT(*) as c FROM users WHERE banned = 1" })).rows[0].c;
  const topSongs = (await db.execute({
    sql: `SELECT audio_url,
           SUM(CASE WHEN vote = 1 THEN 1 ELSE 0 END) as likes,
           SUM(CASE WHEN vote = -1 THEN 1 ELSE 0 END) as dislikes,
           COUNT(*) as total
    FROM ratings WHERE vote != 0
    GROUP BY audio_url ORDER BY total DESC LIMIT 10`
  })).rows;
  const recentActivity = (await db.execute({
    sql: `SELECT '评分' as type, username, audio_url, vote, created_at as time FROM ratings WHERE vote != 0
    UNION ALL
    SELECT '评论' as type, username, audio_url, NULL as vote, created_at as time FROM comments
    UNION ALL
    SELECT '私信' as type, sender as username, receiver as audio_url, NULL as vote, created_at as time FROM messages
    ORDER BY time DESC LIMIT 50`
  })).rows;
  sendJSON(res, {
    totalUsers, totalRatings, totalComments, totalPlays, totalMessages, totalLogs, totalLoginLogs,
    likes, dislikes, bannedUsers, topSongs, recentActivity
  });
}

async function adminUsers(req, res) {
  const result = await db.execute({
    sql: `SELECT u.id, u.username, u.created_at, u.last_login, u.role, u.banned, u.avatar, u.phone,
           (SELECT COUNT(*) FROM ratings WHERE username = u.username AND vote != 0) as rating_count,
           (SELECT COUNT(*) FROM comments WHERE username = u.username) as comment_count,
           (SELECT COUNT(*) FROM play_logs WHERE username = u.username) as play_count,
           (SELECT COUNT(*) FROM messages WHERE sender = u.username OR receiver = u.username) as message_count
    FROM users u ORDER BY u.created_at DESC`
  });
  sendJSON(res, result.rows);
}

// 用户详情：返回该用户的所有数据
async function adminUserDetail(req, res) {
  const q = url.parse(req.url, true).query;
  const username = q.username;
  if (!username) return sendJSON(res, { error: 'username required' }, 400);

  const userResult = await db.execute({
    sql: 'SELECT id, username, avatar, phone, role, banned, created_at, last_login FROM users WHERE username = ?',
    args: [username]
  });
  const user = userResult.rows[0];
  if (!user) return sendJSON(res, { error: '用户不存在' }, 404);

  const ratings = (await db.execute({
    sql: 'SELECT id, audio_url, vote, created_at FROM ratings WHERE username = ? ORDER BY created_at DESC LIMIT 200',
    args: [username]
  })).rows;
  const comments = (await db.execute({
    sql: 'SELECT id, audio_url, vote, text, created_at FROM comments WHERE username = ? ORDER BY created_at DESC LIMIT 200',
    args: [username]
  })).rows;
  const plays = (await db.execute({
    sql: 'SELECT id, audio_url, ip, user_agent, played_at FROM play_logs WHERE username = ? ORDER BY played_at DESC LIMIT 200',
    args: [username]
  })).rows;
  const messages = (await db.execute({
    sql: 'SELECT id, sender, receiver, text, read_flag, created_at FROM messages WHERE sender = ? OR receiver = ? ORDER BY created_at DESC LIMIT 200',
    args: [username, username]
  })).rows;
  const loginLogs = (await db.execute({
    sql: 'SELECT id, success, ip, user_agent, created_at FROM login_logs WHERE username = ? ORDER BY created_at DESC LIMIT 100',
    args: [username]
  })).rows;

  sendJSON(res, { user, ratings, comments, plays, messages, loginLogs });
}

// 删除用户（连带删除其所有数据）— 用 batch 保证原子性
async function adminDeleteUser(req, res) {
  const { username } = await readBody(req);
  if (!username) return sendJSON(res, { error: 'username required' }, 400);
  if (username === 'admin') return sendJSON(res, { error: '不能删除超级管理员' }, 403);

  try {
    await db.batch([
      { sql: 'DELETE FROM ratings WHERE username = ?', args: [username] },
      { sql: 'DELETE FROM comments WHERE username = ?', args: [username] },
      { sql: 'DELETE FROM play_logs WHERE username = ?', args: [username] },
      { sql: 'DELETE FROM messages WHERE sender = ? OR receiver = ?', args: [username, username] },
      { sql: 'DELETE FROM login_logs WHERE username = ?', args: [username] },
      { sql: 'DELETE FROM users WHERE username = ?', args: [username] }
    ]);
    logSystem('WARN', 'USER_DELETE', username, '管理员删除用户及其所有数据', getIP(req));
    sendJSON(res, { success: true });
  } catch (e) {
    sendJSON(res, { error: '删除失败: ' + e.message }, 500);
  }
}

// 修改用户密码
async function adminChangePassword(req, res) {
  const { username, newPassword } = await readBody(req);
  if (!username || !newPassword) return sendJSON(res, { error: '参数缺失' }, 400);
  if (newPassword.length < 4) return sendJSON(res, { error: '密码至少4个字符' }, 400);
  const result = await db.execute({
    sql: 'UPDATE users SET password_hash = ? WHERE username = ?',
    args: [hashPwd(newPassword), username]
  });
  if (result.rowsAffected === 0) return sendJSON(res, { error: '用户不存在' }, 404);
  logSystem('WARN', 'PASSWORD_CHANGE', username, '管理员修改用户密码', getIP(req));
  sendJSON(res, { success: true });
}

// 封禁/解封用户
async function adminToggleBan(req, res) {
  const { username, banned } = await readBody(req);
  if (!username) return sendJSON(res, { error: 'username required' }, 400);
  if (username === 'admin') return sendJSON(res, { error: '不能封禁超级管理员' }, 403);
  const result = await db.execute({
    sql: 'UPDATE users SET banned = ? WHERE username = ?',
    args: [banned ? 1 : 0, username]
  });
  if (result.rowsAffected === 0) return sendJSON(res, { error: '用户不存在' }, 404);
  logSystem('WARN', banned ? 'USER_BAN' : 'USER_UNBAN', username, banned ? '封禁用户' : '解封用户', getIP(req));
  sendJSON(res, { success: true, banned: !!banned });
}

// 重置用户头像
async function adminResetAvatar(req, res) {
  const { username } = await readBody(req);
  if (!username) return sendJSON(res, { error: 'username required' }, 400);
  await db.execute({
    sql: 'UPDATE users SET avatar = NULL WHERE username = ?',
    args: [username]
  });
  logSystem('INFO', 'AVATAR_RESET', username, '管理员重置头像', getIP(req));
  sendJSON(res, { success: true });
}

async function adminRatings(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, audio_url, vote, created_at FROM ratings WHERE vote != 0 ORDER BY created_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminDeleteRating(req, res) {
  const { id } = await readBody(req);
  if (!id) return sendJSON(res, { error: 'id required' }, 400);
  await db.execute({ sql: 'DELETE FROM ratings WHERE id = ?', args: [id] });
  logSystem('WARN', 'RATING_DELETE', 'ID:' + id, '管理员删除评分', getIP(req));
  sendJSON(res, { success: true });
}

async function adminComments(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, audio_url, vote, text, created_at FROM comments ORDER BY created_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminDeleteComment(req, res) {
  const { id } = await readBody(req);
  if (!id) return sendJSON(res, { error: 'id required' }, 400);
  await db.execute({ sql: 'DELETE FROM comments WHERE id = ?', args: [id] });
  logSystem('WARN', 'COMMENT_DELETE', 'ID:' + id, '管理员删除评论', getIP(req));
  sendJSON(res, { success: true });
}

async function adminPlays(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, audio_url, ip, user_agent, played_at FROM play_logs ORDER BY played_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminDeletePlay(req, res) {
  const { id } = await readBody(req);
  if (!id) return sendJSON(res, { error: 'id required' }, 400);
  await db.execute({ sql: 'DELETE FROM play_logs WHERE id = ?', args: [id] });
  sendJSON(res, { success: true });
}

async function adminClearPlays(req, res) {
  await db.execute({ sql: 'DELETE FROM play_logs' });
  logSystem('WARN', 'PLAYS_CLEAR', '-', '管理员清空所有播放日志', getIP(req));
  sendJSON(res, { success: true });
}

async function adminMessages(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, sender, receiver, text, read_flag, created_at FROM messages ORDER BY created_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminDeleteMessage(req, res) {
  const { id } = await readBody(req);
  if (!id) return sendJSON(res, { error: 'id required' }, 400);
  await db.execute({ sql: 'DELETE FROM messages WHERE id = ?', args: [id] });
  logSystem('WARN', 'MESSAGE_DELETE', 'ID:' + id, '管理员删除私信', getIP(req));
  sendJSON(res, { success: true });
}

async function adminLogs(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, level, action, target, detail, ip, created_at FROM system_logs ORDER BY created_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminDeleteLog(req, res) {
  const { id } = await readBody(req);
  if (!id) return sendJSON(res, { error: 'id required' }, 400);
  await db.execute({ sql: 'DELETE FROM system_logs WHERE id = ?', args: [id] });
  sendJSON(res, { success: true });
}

async function adminClearLogs(req, res) {
  await db.execute({ sql: 'DELETE FROM system_logs' });
  sendJSON(res, { success: true });
}

async function adminLoginLogs(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, success, ip, user_agent, created_at FROM login_logs ORDER BY created_at DESC LIMIT 2000'
  });
  sendJSON(res, result.rows);
}

async function adminClearLoginLogs(req, res) {
  await db.execute({ sql: 'DELETE FROM login_logs' });
  sendJSON(res, { success: true });
}

async function adminExport(req, res) {
  const users = (await db.execute({ sql: 'SELECT username, avatar, phone, role, banned, created_at, last_login FROM users' })).rows;
  const ratings = (await db.execute({ sql: 'SELECT username, audio_url, vote, created_at FROM ratings WHERE vote != 0' })).rows;
  const comments = (await db.execute({ sql: 'SELECT username, audio_url, vote, text, created_at FROM comments' })).rows;
  const plays = (await db.execute({ sql: 'SELECT username, audio_url, played_at FROM play_logs' })).rows;
  const messages = (await db.execute({ sql: 'SELECT sender, receiver, text, read_flag, created_at FROM messages' })).rows;
  const logs = (await db.execute({ sql: 'SELECT level, action, target, detail, ip, created_at FROM system_logs' })).rows;
  const loginLogs = (await db.execute({ sql: 'SELECT username, success, ip, user_agent, created_at FROM login_logs' })).rows;
  sendJSON(res, { users, ratings, comments, plays, messages, logs, loginLogs, exportedAt: new Date().toISOString() });
}

// ============ 管理员反馈管理 API ============
// 查看所有反馈
async function adminGetFeedback(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, message, attachment_data, attachment_name, attachment_type, admin_reply, replied_at, ip, created_at FROM feedback ORDER BY created_at DESC LIMIT 500'
  });
  sendJSON(res, result.rows);
}
// 回复反馈
async function adminReplyFeedback(req, res) {
  const { id, reply } = await readBody(req);
  if (!id || !reply) return sendJSON(res, { error: '缺少反馈ID或回复内容' }, 400);
  await db.execute({
    sql: "UPDATE feedback SET admin_reply = ?, replied_at = datetime('now') WHERE id = ?",
    args: [reply, id]
  });
  sendJSON(res, { success: true });
}
// 删除反馈
async function adminDeleteFeedback(req, res) {
  const { id } = await readBody(req);
  await db.execute({ sql: 'DELETE FROM feedback WHERE id = ?', args: [id] });
  sendJSON(res, { success: true });
}

// ============ 管理员社区管理 API ============
// 查看所有社区帖子
async function adminGetCommunity(req, res) {
  const result = await db.execute({
    sql: 'SELECT id, username, content, attachment_data, attachment_name, attachment_type, ip, created_at FROM community_posts ORDER BY created_at DESC LIMIT 500'
  });
  sendJSON(res, result.rows);
}
// 删除社区帖子
async function adminDeleteCommunity(req, res) {
  const { id } = await readBody(req);
  await db.execute({ sql: 'DELETE FROM community_posts WHERE id = ?', args: [id] });
  sendJSON(res, { success: true });
}

// ============ ADMIN DASHBOARD HTML ============
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=5">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#08080a">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>NCS Ratings · 超级管理后台</title>
<style>
:root{
  --bg:#08080a;--bg2:#131316;--bg3:#1a1a20;--bg4:#222230;--bg5:#2a2a35;
  --tx:#f4f4f5;--tx2:#d4d4d8;--tx3:#a1a1aa;--tx4:#71717a;
  --accent:#22c55e;--accent2:#3b82f6;--red:#ef4444;--yellow:#f59e0b;--purple:#a855f7;--cyan:#06b6d4;
  --bd:rgba(255,255,255,0.08);--bd2:rgba(255,255,255,0.14);--radius:12px;
  --shadow:0 10px 30px -10px rgba(0,0,0,0.6);
  --vh:1vh; /* 动态视口高度变量，JS 会更新此值修复 iOS Safari 黑屏 */
  --safe-top:env(safe-area-inset-top,0px);
  --safe-bottom:env(safe-area-inset-bottom,0px);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100%;-webkit-text-size-adjust:100%}
body{height:100%;background:var(--bg);color:var(--tx);font-family:system-ui,-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei','Segoe UI',sans-serif;font-size:13.5px;line-height:1.5;background-image:radial-gradient(1000px 500px at 90% -10%,rgba(34,197,94,0.05),transparent 60%),radial-gradient(800px 400px at -10% 30%,rgba(59,130,246,0.04),transparent 60%);background-attachment:fixed;overflow-x:hidden}
a{color:var(--accent2);text-decoration:none;cursor:pointer}
button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit}
input,select,textarea{font-family:inherit;font-size:inherit;color:inherit;background:transparent;border:none;outline:none}

/* Layout — 使用 --vh 变量修复 iOS Safari 黑屏 */
.app{display:grid;grid-template-columns:240px 1fr;height:100vh;height:calc(var(--vh,1vh) * 100);height:100dvh;min-height:100vh;min-height:calc(var(--vh,1vh) * 100)}
.sidebar{background:linear-gradient(180deg,#08080a,#0c0c0f);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;position:fixed;width:240px;height:100vh;height:calc(var(--vh,1vh) * 100);height:100dvh;left:0;top:0;z-index:20;padding-top:var(--safe-top);padding-bottom:var(--safe-bottom)}
.sidebar-brand{padding:22px 22px 18px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--bd)}
.brand-logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(145deg,#a855f7,#7c3aed);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 14px rgba(168,85,247,0.35)}
.brand-name{font-weight:800;font-size:15px;letter-spacing:-0.2px}
.brand-name small{display:block;font-size:9.5px;color:var(--tx4);font-weight:600;letter-spacing:1.5px;text-transform:uppercase;margin-top:2px}
.nav{flex:1;overflow-y:auto;padding:10px 12px}
.nav-item{display:flex;align-items:center;gap:11px;padding:10px 13px;border-radius:8px;color:var(--tx3);font-weight:600;font-size:13px;transition:all .15s;margin-bottom:2px;user-select:none}
.nav-item:hover{color:var(--tx);background:var(--bg3)}
.nav-item.active{color:#fff;background:linear-gradient(180deg,var(--bg4),var(--bg3));box-shadow:inset 0 1px 0 rgba(255,255,255,0.05)}
.nav-item.active::before{content:'';position:absolute;left:0;width:3px;height:20px;background:var(--purple);border-radius:0 3px 3px 0;box-shadow:0 0 10px rgba(168,85,247,0.5)}
.nav-item{position:relative}
.nav-item .ico{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-item .count{margin-left:auto;background:var(--bg4);color:var(--tx3);font-size:10px;font-weight:700;padding:2px 7px;border-radius:99px}
.nav-item.active .count{background:var(--purple);color:#fff}
.sidebar-footer{padding:12px 18px;border-top:1px solid var(--bd);font-size:10.5px;color:var(--tx4);line-height:1.6}
.sidebar-footer b{color:var(--tx2)}

.main{margin-left:240px;display:flex;flex-direction:column;height:100vh;height:calc(var(--vh,1vh) * 100);height:100dvh;min-height:100vh;min-height:calc(var(--vh,1vh) * 100);overflow:hidden}
.topbar{height:60px;padding:0 28px;display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--bd);background:rgba(8,8,10,0.85);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);position:sticky;top:0;z-index:10;flex-shrink:0}
.topbar h1{font-size:17px;font-weight:800;display:flex;align-items:center;gap:9px}
.topbar .sub{color:var(--tx4);font-size:11.5px;font-weight:600;margin-left:4px}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.db-status{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;padding:5px 11px;border-radius:99px;background:rgba(34,197,94,0.1);color:#4ade80}
.db-dot{width:7px;height:7px;border-radius:50%;background:var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.content{flex:1;overflow-y:auto;padding:24px 28px 40px}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}
.stat-card{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);padding:18px;display:flex;align-items:center;gap:14px;transition:all .2s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;inset:0;background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent);pointer-events:none}
.stat-card:hover{border-color:var(--bd2);transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-icon{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.stat-icon.green{background:rgba(34,197,94,0.15)}
.stat-icon.blue{background:rgba(59,130,246,0.15)}
.stat-icon.yellow{background:rgba(245,158,11,0.15)}
.stat-icon.purple{background:rgba(168,85,247,0.15)}
.stat-icon.red{background:rgba(239,68,68,0.15)}
.stat-icon.cyan{background:rgba(6,182,212,0.15)}
.stat-value{font-size:24px;font-weight:800;line-height:1;background:linear-gradient(180deg,#fff,#a1a1aa);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.stat-label{font-size:11px;color:var(--tx4);margin-top:4px;font-weight:600;letter-spacing:.5px}

/* Section */
.section{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius);margin-bottom:22px;overflow:hidden}
.section-head{padding:15px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.section-head h2{font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px}
.section-head .h-actions{display:flex;gap:8px;align-items:center}

/* Buttons */
.btn{padding:7px 14px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);cursor:pointer;font-size:12px;font-weight:600;transition:all .15s;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.btn:hover{background:var(--bg4);border-color:var(--bd2);color:var(--tx)}
.btn.primary{background:linear-gradient(180deg,#22c55e,#16a34a);color:#052e16;border-color:transparent}
.btn.primary:hover{opacity:.92;transform:translateY(-1px)}
.btn.danger{background:rgba(239,68,68,0.12);color:#f87171;border-color:rgba(239,68,68,0.25)}
.btn.danger:hover{background:rgba(239,68,68,0.2);color:#fca5a5}
.btn.warn{background:rgba(245,158,11,0.12);color:#fbbf24;border-color:rgba(245,158,11,0.25)}
.btn.warn:hover{background:rgba(245,158,11,0.2)}
.btn.purple{background:rgba(168,85,247,0.12);color:#c084fc;border-color:rgba(168,85,247,0.25)}
.btn.purple:hover{background:rgba(168,85,247,0.2)}
.btn.sm{padding:5px 10px;font-size:11px}
.btn.icon{padding:5px 8px;font-size:13px}

/* Search */
.search-bar{padding:12px 20px;border-bottom:1px solid var(--bd);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.search-bar input{flex:1;min-width:200px;padding:8px 14px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx);font-size:12.5px}
.search-bar input:focus{border-color:var(--purple)}
.search-bar input::placeholder{color:var(--tx4)}

/* Table */
.table-wrap{overflow-x:auto;max-height:calc(100vh - 320px);overflow-y:auto}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:var(--bg2);padding:10px 14px;text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--tx3);font-weight:700;border-bottom:1px solid var(--bd);white-space:nowrap;z-index:2}
td{padding:9px 14px;border-bottom:1px solid var(--bd);font-size:12.5px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover{background:var(--bg3)}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10.5px;font-weight:700;white-space:nowrap}
.badge.green{background:rgba(34,197,94,0.15);color:#4ade80}
.badge.red{background:rgba(239,68,68,0.15);color:#f87171}
.badge.blue{background:rgba(59,130,246,0.15);color:#60a5fa}
.badge.yellow{background:rgba(245,158,11,0.15);color:#fbbf24}
.badge.purple{background:rgba(168,85,247,0.15);color:#c084fc}
.badge.gray{background:rgba(161,161,170,0.15);color:#a1a1aa}
.empty{padding:40px;text-align:center;color:var(--tx4);font-size:13px}
.row-actions{display:flex;gap:4px;white-space:nowrap}

/* Top songs */
.top-songs{padding:6px 0}
.top-song{display:flex;align-items:center;gap:12px;padding:8px 20px}
.top-song:hover{background:var(--bg3)}
.rank{width:28px;height:28px;border-radius:8px;background:var(--bg4);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.rank.top3{background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff}
.song-info{flex:1;min-width:0}
.song-name{font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.song-stats{font-size:10.5px;color:var(--tx4);margin-top:2px}
.bar-mini{width:80px;height:4px;border-radius:99px;background:var(--bg4);overflow:hidden;flex-shrink:0}
.bar-mini-fill{height:100%;border-radius:99px}

/* Activity */
.activity-item{display:flex;align-items:center;gap:10px;padding:8px 20px;font-size:12.5px}
.activity-item:hover{background:var(--bg3)}
.activity-icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0}

/* Modal */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--bd2);border-radius:14px;max-width:600px;width:100%;max-height:85vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 30px 60px -20px rgba(0,0,0,0.8)}
.modal-head{padding:16px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between}
.modal-head h3{font-size:15px;font-weight:700}
.modal-close{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;color:var(--tx3)}
.modal-close:hover{background:var(--bg3);color:var(--tx)}
.modal-body{padding:20px;overflow-y:auto;flex:1}
.modal-foot{padding:14px 20px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:8px}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;font-weight:700;color:var(--tx3);margin-bottom:6px;letter-spacing:.5px;text-transform:uppercase}
.field input,.field textarea{width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx);font-size:13px}
.field input:focus,.field textarea:focus{border-color:var(--purple)}
.field textarea{resize:vertical;min-height:60px}
.user-detail-block{margin-bottom:18px}
.user-detail-block h4{font-size:12px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.user-detail-block .info-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;font-size:12px}
.user-detail-block .info-grid div{background:var(--bg3);padding:8px 12px;border-radius:8px;border:1px solid var(--bd)}
.user-detail-block .info-grid b{color:var(--tx3);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.3px;display:block;margin-bottom:2px}
.user-detail-block .info-grid span{color:var(--tx);font-weight:600}

/* Toast */
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--bg4);border:1px solid var(--bd2);border-radius:10px;padding:12px 20px;font-size:13px;font-weight:600;z-index:200;display:none;align-items:center;gap:10px;box-shadow:var(--shadow)}
.toast.show{display:flex}
.toast.success{border-color:rgba(34,197,94,0.4)}
.toast.error{border-color:rgba(239,68,68,0.4)}

/* Responsive */
/* 平板设备适配 */
@media(max-width:1024px){
  .app{grid-template-columns:1fr}
  .sidebar{transform:translateX(-100%);transition:transform .25s ease;-webkit-transition:transform .25s ease}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .menu-toggle{display:flex !important}
  .content{padding:16px 20px}
}
.menu-toggle{display:none;width:34px;height:34px;border-radius:8px;align-items:center;justify-content:center;font-size:18px;background:var(--bg3);border:1px solid var(--bd);flex-shrink:0}
/* 手机设备适配 */
@media(max-width:768px){
  .content{padding:12px 14px 20px}
  .topbar{padding:0 12px 0 14px;gap:8px;height:54px}
  .topbar h1{font-size:15px}
  .topbar .sub{display:none}
  .topbar-right{gap:6px}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .search-bar{padding:10px 12px}
  td,th{padding:7px 9px;font-size:11px}
  .btn.sm{padding:5px 10px;font-size:11px}
}
/* 超小屏幕适配 */
@media(max-width:480px){
  .stats-grid{grid-template-columns:1fr}
  .topbar-right .db-status{display:none}
  .content{padding:10px 10px 16px}
  td,th{padding:6px 7px;font-size:10.5px}
  .modal{width:100% !important;max-width:100% !important;border-radius:0;border:none}
  .modal-body{padding:14px !important}
}
/* 横屏模式适配 */
@media(max-width:900px) and (orientation:landscape) and (max-height:500px){
  .sidebar-brand{padding:12px 18px}
  .brand-logo{width:30px;height:30px;font-size:14px}
  .nav-item{padding:7px 11px;font-size:12px}
  .topbar{height:48px}
}
/* 触摸设备优化 */
@media(hover:none) and (pointer:coarse){
  .nav-item:hover{background:transparent;color:var(--tx3)}
  .nav-item:active{background:var(--bg3)}
  .btn:active{transform:scale(0.96)}
  button:active{opacity:0.7}
}
/* Safari 特定修复 */
@media not all and (min-resolution:.001dpcm){
  @supports(-webkit-touch-callout:none){
    .sidebar{padding-top:max(var(--safe-top),env(safe-area-inset-top,0px))}
    .topbar{padding-top:var(--safe-top)}
    body{height:-webkit-fill-available}
    .app{height:-webkit-fill-available}
  }
}
</style>
</head>
<body>
<script>
// ============ 设备检测 & Safari 兼容性修复 ============
(function(){
  var ua=navigator.userAgent;
  var isMobile=/Android|webOS|iPhone|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)||(navigator.maxTouchPoints>1&&window.innerWidth<768);
  var isTablet=/iPad|Tablet|PlayBook|Silk/i.test(ua)||(navigator.maxTouchPoints>1&&window.innerWidth>=768&&window.innerWidth<=1024);
  var isDesktop=!isMobile&&!isTablet;
  var isIOS=/iPad|iPhone|iPod/.test(ua);
  var isSafari=/^((?!chrome|android|crios|fxios).)*safari/i.test(ua);
  var dpr=window.devicePixelRatio||1;
  var orient=window.innerWidth>window.innerHeight?'landscape':'portrait';
  var cls=[
    isMobile?'is-mobile':'',
    isTablet?'is-tablet':'',
    isDesktop?'is-desktop':'',
    isIOS?'is-ios':'',
    isSafari?'is-safari':'',
    'dpr-'+(dpr>=3?'3x':dpr>=2?'2x':'1x'),
    'orient-'+orient
  ].filter(Boolean).join(' ');
  document.documentElement.className=cls;
  // 修复 iOS Safari 100vh 黑屏问题：动态设置 --vh CSS 变量
  function setVH(){
    var h=window.innerHeight;
    document.documentElement.style.setProperty('--vh',(h*0.01)+'px');
    // Safari 兼容：同时设置 -webkit-fill-available 回退
    if(isIOS){document.body.style.height=h+'px';}
  }
  setVH();
  // 防抖：避免频繁触发
  var rt;
  window.addEventListener('resize',function(){clearTimeout(rt);rt=setTimeout(setVH,100);});
  window.addEventListener('orientationchange',function(){setTimeout(setVH,200);});
  // iOS Safari 可视性修复：从后台切回时重新计算
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden){setTimeout(setVH,300);}
  });
})();
</script>
<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      <div class="brand-logo">⚡</div>
      <div class="brand-name">超级后台<small>God Mode</small></div>
    </div>
    <nav class="nav" id="nav">
      <div class="nav-item active" data-view="dashboard" onclick="switchView('dashboard')"><span class="ico">📊</span> 仪表盘</div>
      <div class="nav-item" data-view="users" onclick="switchView('users')"><span class="ico">👥</span> 用户管理 <span class="count" id="cntUsers">0</span></div>
      <div class="nav-item" data-view="ratings" onclick="switchView('ratings')"><span class="ico">👍</span> 评分记录 <span class="count" id="cntRatings">0</span></div>
      <div class="nav-item" data-view="comments" onclick="switchView('comments')"><span class="ico">💬</span> 评论管理 <span class="count" id="cntComments">0</span></div>
      <div class="nav-item" data-view="plays" onclick="switchView('plays')"><span class="ico">🎧</span> 播放记录 <span class="count" id="cntPlays">0</span></div>
      <div class="nav-item" data-view="messages" onclick="switchView('messages')"><span class="ico">✉️</span> 私信监控 <span class="count" id="cntMsgs">0</span></div>
      <div class="nav-item" data-view="logs" onclick="switchView('logs')"><span class="ico">📜</span> 系统日志 <span class="count" id="cntLogs">0</span></div>
      <div class="nav-item" data-view="loginLogs" onclick="switchView('loginLogs')"><span class="ico">🔐</span> 登录日志 <span class="count" id="cntLogin">0</span></div>
      <div class="nav-item" data-view="feedback" onclick="switchView('feedback')"><span class="ico">📮</span> 反馈管理 <span class="count" id="cntFeedback">0</span></div>
      <div class="nav-item" data-view="community" onclick="switchView('community')"><span class="ico">🌐</span> 社区管理 <span class="count" id="cntCommunity">0</span></div>
      <div class="nav-item" data-view="activity" onclick="switchView('activity')"><span class="ico">⚡</span> 实时活动</div>
    </nav>
    <div class="sidebar-footer">
      <b>NCS Ratings DB</b><br>
      SQLite · WAL Mode<br>
      <span id="dbPathShort"></span>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
      <h1 id="viewTitle">📊 仪表盘</h1>
      <span class="sub" id="viewSub">总览所有数据</span>
      <div class="topbar-right">
        <span class="db-status"><span class="db-dot"></span> 数据库已连接</span>
        <button class="btn sm" onclick="exportJSON()">⬇ 导出全部</button>
        <button class="btn sm primary" onclick="loadAll()">🔄 刷新</button>
      </div>
    </div>
    <div class="content" id="content"></div>
  </main>
</div>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal" id="modalBox">
    <div class="modal-head">
      <h3 id="modalTitle">弹窗</h3>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
    <div class="modal-foot" id="modalFoot"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentView='dashboard', overviewData=null, cachedData={};
const shortUrl=u=>{if(!u)return'-';try{return decodeURIComponent(u.split('/').pop()||u).slice(0,60)}catch(e){return u.slice(0,60)}};
const esc=s=>{if(s==null)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML};
const $=id=>document.getElementById(id);

function toast(msg,type){
  const t=$('toast');t.textContent=msg;t.className='toast show '+(type||'');
  setTimeout(()=>t.className='toast',2500);
}

async function fetchJSON(url,opts){
  try{
    const r=await fetch(url,opts||{});
    const data=await r.json();
    if(!r.ok) return {error:data.error||('HTTP '+r.status)};
    return data;
  }catch(e){return {error:e.message}}
}
async function postJSON(url,body){
  return fetchJSON(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
}

function render(html){$('content').innerHTML=html}

// ============ DASHBOARD ============
async function loadDashboard(){
  $('viewTitle').textContent='📊 仪表盘';
  $('viewSub').textContent='总览所有数据';
  overviewData=await fetchJSON('/admin/api/overview');
  if(overviewData.error){toast(overviewData.error,'error');return}

  // Update nav counts
  $('cntUsers').textContent=overviewData.totalUsers||0;
  $('cntRatings').textContent=overviewData.totalRatings||0;
  $('cntComments').textContent=overviewData.totalComments||0;
  $('cntPlays').textContent=overviewData.totalPlays||0;
  $('cntMsgs').textContent=overviewData.totalMessages||0;
  $('cntLogs').textContent=overviewData.totalLogs||0;
  $('cntLogin').textContent=overviewData.totalLoginLogs||0;

  const o=overviewData;
  render(\`
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-icon green">👥</div><div><div class="stat-value">\${o.totalUsers}</div><div class="stat-label">注册用户</div></div></div>
      <div class="stat-card"><div class="stat-icon red">🚫</div><div><div class="stat-value">\${o.bannedUsers}</div><div class="stat-label">封禁用户</div></div></div>
      <div class="stat-card"><div class="stat-icon blue">📊</div><div><div class="stat-value">\${o.totalRatings}</div><div class="stat-label">评分总数</div></div></div>
      <div class="stat-card"><div class="stat-icon yellow">💬</div><div><div class="stat-value">\${o.totalComments}</div><div class="stat-label">评论总数</div></div></div>
      <div class="stat-card"><div class="stat-icon purple">🎧</div><div><div class="stat-value">\${o.totalPlays}</div><div class="stat-label">播放次数</div></div></div>
      <div class="stat-card"><div class="stat-icon cyan">✉️</div><div><div class="stat-value">\${o.totalMessages}</div><div class="stat-label">私信总数</div></div></div>
      <div class="stat-card"><div class="stat-icon green">📜</div><div><div class="stat-value">\${o.totalLogs}</div><div class="stat-label">系统日志</div></div></div>
      <div class="stat-card"><div class="stat-icon red">🔐</div><div><div class="stat-value">\${o.totalLoginLogs}</div><div class="stat-label">登录日志</div></div></div>
    </div>
    <div class="section">
      <div class="section-head"><h2>🔥 热门歌曲 Top 10</h2></div>
      <div class="top-songs" id="topSongs"><div class="empty">加载中...</div></div>
    </div>
    <div class="section">
      <div class="section-head"><h2>⚡ 最近活动</h2></div>
      <div id="recentActivity"><div class="empty">加载中...</div></div>
    </div>
  \`);

  // Top songs
  const ts=$('topSongs');
  if(!o.topSongs||o.topSongs.length===0){ts.innerHTML='<div class="empty">暂无评分数据</div>'}
  else{
    ts.innerHTML=o.topSongs.map((s,i)=>{
      const total=s.likes+s.dislikes;const likePct=total?Math.round(s.likes/total*100):0;
      return '<div class="top-song">'+
        '<div class="rank'+(i<3?' top3':'')+'">'+(i+1)+'</div>'+
        '<div class="song-info"><div class="song-name">'+esc(shortUrl(s.audio_url))+'</div>'+
        '<div class="song-stats">👍 '+s.likes+' · 👎 '+s.dislikes+' · '+likePct+'% 好评</div></div>'+
        '<div class="bar-mini"><div class="bar-mini-fill" style="width:'+likePct+'%;background:'+(likePct>60?'#22c55e':likePct>40?'#f59e0b':'#ef4444')+'"></div></div>'+
      '</div>';
    }).join('');
  }

  // Recent activity
  const ra=$('recentActivity');
  if(!o.recentActivity||o.recentActivity.length===0){ra.innerHTML='<div class="empty">暂无活动</div>'}
  else{
    ra.innerHTML=o.recentActivity.map(a=>{
      const icon=a.type==='评分'?'👍':a.type==='评论'?'💬':'✉️';
      const color=a.type==='评分'?'green':a.type==='评论'?'blue':'purple';
      return '<div class="activity-item">'+
        '<div class="activity-icon" style="background:rgba(168,85,247,0.1)">'+icon+'</div>'+
        '<span class="badge '+color+'">'+a.type+'</span>'+
        '<span style="font-weight:600">'+esc(a.username)+'</span>'+
        '<span style="color:var(--tx3);font-size:11.5px">'+esc(shortUrl(a.audio_url))+'</span>'+
        (a.vote===1?'<span class="badge green">👍</span>':a.vote===-1?'<span class="badge red">👎</span>':'')+
        '<span style="margin-left:auto;color:var(--tx4);font-size:11px">'+esc(a.time)+'</span>'+
      '</div>';
    }).join('');
  }
}

// ============ USERS ============
async function loadUsers(){
  $('viewTitle').textContent='👥 用户管理';
  $('viewSub').textContent='查看、删除、改密码、封禁 — 神的权力';
  render('<div class="section"><div class="search-bar"><input id="searchInput" placeholder="搜索用户名..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/users');
  if(rows.error){toast(rows.error,'error');return}
  cachedData.users=rows;
  renderUsersTable(rows);
}
function renderUsersTable(rows){
  const wrap=$('tableWrap');
  if(!rows||rows.length===0){wrap.innerHTML='<div class="empty">暂无用户</div>';return}
  let html='<table><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>状态</th><th>评分数</th><th>评论数</th><th>播放数</th><th>私信数</th><th>注册时间</th><th>最后登录</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{
    const status=r.banned?'<span class="badge red">已封禁</span>':'<span class="badge green">正常</span>';
    const role=r.role==='admin'?'<span class="badge purple">管理员</span>':'<span class="badge gray">用户</span>';
    html+='<tr data-username="'+esc(r.username)+'">'+
      '<td>'+r.id+'</td>'+
      '<td style="font-weight:700">'+esc(r.username)+'</td>'+
      '<td>'+role+'</td>'+
      '<td>'+status+'</td>'+
      '<td><span class="badge green">'+r.rating_count+'</span></td>'+
      '<td><span class="badge blue">'+r.comment_count+'</span></td>'+
      '<td><span class="badge yellow">'+r.play_count+'</span></td>'+
      '<td><span class="badge purple">'+r.message_count+'</span></td>'+
      '<td>'+esc(r.created_at)+'</td>'+
      '<td>'+(r.last_login?esc(r.last_login):'<span style="color:var(--tx4)">从未</span>')+'</td>'+
      '<td><div class="row-actions">'+
        '<button class="btn sm purple" onclick="userDetail(\\''+esc(r.username)+'\\')">👁 详情</button>'+
        '<button class="btn sm warn" onclick="changePwdModal(\\''+esc(r.username)+'\\')">🔑 改密</button>'+
        (r.banned?
          '<button class="btn sm" onclick="toggleBan(\\''+esc(r.username)+'\\',false)">✅ 解封</button>':
          '<button class="btn sm warn" onclick="toggleBan(\\''+esc(r.username)+'\\',true)">🚫 封禁</button>')+
        '<button class="btn sm danger" onclick="deleteUser(\\''+esc(r.username)+'\\')">🗑 删除</button>'+
      '</div></td>'+
    '</tr>';
  });
  html+='</tbody></table>';
  wrap.innerHTML=html;
}
async function userDetail(username){
  $('modalTitle').textContent='👁 用户详情 · '+username;
  $('modalBody').innerHTML='<div class="empty">加载中...</div>';
  $('modalFoot').innerHTML='<button class="btn" onclick="closeModal()">关闭</button>';
  openModal();
  const d=await fetchJSON('/admin/api/user/detail?username='+encodeURIComponent(username));
  if(d.error){$('modalBody').innerHTML='<div class="empty">'+d.error+'</div>';return}
  const u=d.user;
  let html='<div class="user-detail-block">'+
    '<h4>📋 基本信息</h4>'+
    '<div class="info-grid">'+
      '<div><b>ID</b><span>'+u.id+'</span></div>'+
      '<div><b>用户名</b><span>'+esc(u.username)+'</span></div>'+
      '<div><b>角色</b><span>'+esc(u.role||'user')+'</span></div>'+
      '<div><b>状态</b><span>'+(u.banned?'已封禁':'正常')+'</span></div>'+
      '<div><b>手机号</b><span>'+esc(u.phone||'未绑定')+'</span></div>'+
      '<div><b>注册时间</b><span>'+esc(u.created_at)+'</span></div>'+
      '<div><b>最后登录</b><span>'+esc(u.last_login||'从未')+'</span></div>'+
    '</div></div>';
  html+='<div class="user-detail-block"><h4>👍 评分历史 ('+d.ratings.length+')</h4>';
  if(d.ratings.length===0) html+='<div class="empty">无评分</div>';
  else{html+='<div class="table-wrap" style="max-height:200px"><table><thead><tr><th>歌曲</th><th>评分</th><th>时间</th><th>操作</th></tr></thead><tbody>';
    d.ratings.forEach(r=>{html+='<tr><td>'+esc(shortUrl(r.audio_url))+'</td><td>'+(r.vote===1?'<span class="badge green">👍</span>':'<span class="badge red">👎</span>')+'</td><td>'+esc(r.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteRatingById('+r.id+')">🗑</button></td></tr>'});
    html+='</tbody></table></div>'}
  html+='</div>';
  html+='<div class="user-detail-block"><h4>💬 评论历史 ('+d.comments.length+')</h4>';
  if(d.comments.length===0) html+='<div class="empty">无评论</div>';
  else{html+='<div class="table-wrap" style="max-height:200px"><table><thead><tr><th>歌曲</th><th>内容</th><th>时间</th><th>操作</th></tr></thead><tbody>';
    d.comments.forEach(c=>{html+='<tr><td>'+esc(shortUrl(c.audio_url))+'</td><td style="max-width:200px">'+esc(c.text)+'</td><td>'+esc(c.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteCommentById('+c.id+')">🗑</button></td></tr>'});
    html+='</tbody></table></div>'}
  html+='</div>';
  html+='<div class="user-detail-block"><h4>🎧 播放历史 ('+d.plays.length+')</h4>';
  if(d.plays.length===0) html+='<div class="empty">无播放记录</div>';
  else{html+='<div class="table-wrap" style="max-height:200px"><table><thead><tr><th>歌曲</th><th>IP</th><th>时间</th></tr></thead><tbody>';
    d.plays.slice(0,50).forEach(p=>{html+='<tr><td>'+esc(shortUrl(p.audio_url))+'</td><td>'+esc(p.ip||'-')+'</td><td>'+esc(p.played_at)+'</td></tr>'});
    html+='</tbody></table></div>'}
  html+='</div>';
  html+='<div class="user-detail-block"><h4>✉️ 私信记录 ('+d.messages.length+')</h4>';
  if(d.messages.length===0) html+='<div class="empty">无私信</div>';
  else{html+='<div class="table-wrap" style="max-height:200px"><table><thead><tr><th>方向</th><th>对方</th><th>内容</th><th>已读</th><th>时间</th></tr></thead><tbody>';
    d.messages.forEach(m=>{
      const dir=m.sender===u.username?'<span class="badge blue">发送</span>':'<span class="badge green">接收</span>';
      const other=m.sender===u.username?m.receiver:m.sender;
      html+='<tr><td>'+dir+'</td><td>'+esc(other)+'</td><td style="max-width:200px">'+esc(m.text)+'</td><td>'+(m.read_flag?'✅':'⭕')+'</td><td>'+esc(m.created_at)+'</td></tr>'});
    html+='</tbody></table></div>'}
  html+='</div>';
  html+='<div class="user-detail-block"><h4>🔐 登录记录 ('+d.loginLogs.length+')</h4>';
  if(d.loginLogs.length===0) html+='<div class="empty">无登录记录</div>';
  else{html+='<div class="table-wrap" style="max-height:200px"><table><thead><tr><th>结果</th><th>IP</th><th>UA</th><th>时间</th></tr></thead><tbody>';
    d.loginLogs.forEach(l=>{html+='<tr><td>'+(l.success?'<span class="badge green">成功</span>':'<span class="badge red">失败</span>')+'</td><td>'+esc(l.ip)+'</td><td style="max-width:200px;font-size:11px">'+esc(l.user_agent)+'</td><td>'+esc(l.created_at)+'</td></tr>'});
    html+='</tbody></table></div>'}
  html+='</div>';
  $('modalBody').innerHTML=html;
}
function changePwdModal(username){
  $('modalTitle').textContent='🔑 修改密码 · '+username;
  $('modalBody').innerHTML='<div class="field"><label>新密码（至少4位）</label><input id="newPwd" type="text" placeholder="输入新密码"></div>';
  $('modalFoot').innerHTML='<button class="btn" onclick="closeModal()">取消</button><button class="btn primary" onclick="doChangePwd(\\''+esc(username)+'\\')">确认修改</button>';
  openModal();
}
async function doChangePwd(username){
  const pwd=$('newPwd').value.trim();
  if(pwd.length<4){toast('密码至少4位','error');return}
  const r=await postJSON('/admin/api/user/password',{username,newPassword:pwd});
  if(r.error){toast(r.error,'error');return}
  toast('✅ 密码已修改','success');closeModal();
  logSystem('管理员修改 '+username+' 的密码');
}
async function toggleBan(username,ban){
  if(!confirm(ban?'确认封禁用户 '+username+'？被封禁用户将无法登录。':'确认解封用户 '+username+'？'))return;
  const r=await postJSON('/admin/api/user/ban',{username,banned:ban});
  if(r.error){toast(r.error,'error');return}
  toast(ban?'🚫 已封禁':'✅ 已解封','success');
  loadUsers();
}
async function deleteUser(username){
  if(!confirm('⚠️ 确认删除用户 '+username+'？\\n\\n这将永久删除该用户及其所有评分、评论、播放记录、私信、登录日志！\\n\\n此操作不可撤销！'))return;
  if(!confirm('再次确认：真的要删除 '+username+' 的所有数据吗？'))return;
  const r=await postJSON('/admin/api/user/delete',{username});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 用户已删除','success');
  loadUsers();
  loadOverviewCounts();
}

// ============ RATINGS ============
async function loadRatings(){
  $('viewTitle').textContent='👍 评分记录';
  $('viewSub').textContent='所有用户的评分历史，可单条删除';
  render('<div class="section"><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、歌曲..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/ratings');
  if(rows.error){toast(rows.error,'error');return}
  cachedData.ratings=rows;
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无评分</div>';return}
  let html='<table><thead><tr><th>ID</th><th>用户名</th><th>歌曲</th><th>评分</th><th>时间</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{html+='<tr><td>'+r.id+'</td><td style="font-weight:600">'+esc(r.username)+'</td><td>'+esc(shortUrl(r.audio_url))+'</td><td>'+(r.vote===1?'<span class="badge green">👍 好评</span>':'<span class="badge red">👎 差评</span>')+'</td><td>'+esc(r.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteRatingById('+r.id+')">🗑 删除</button></td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function deleteRatingById(id){
  if(!confirm('确认删除评分 #'+id+'？'))return;
  const r=await postJSON('/admin/api/rating/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');
  if(currentView==='ratings')loadRatings();
}

// ============ COMMENTS ============
async function loadComments(){
  $('viewTitle').textContent='💬 评论管理';
  $('viewSub').textContent='所有评论，可单条删除';
  render('<div class="section"><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、歌曲、评论内容..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/comments');
  if(rows.error){toast(rows.error,'error');return}
  cachedData.comments=rows;
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无评论</div>';return}
  let html='<table><thead><tr><th>ID</th><th>用户名</th><th>歌曲</th><th>评分</th><th>评论内容</th><th>时间</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{html+='<tr><td>'+r.id+'</td><td style="font-weight:600">'+esc(r.username)+'</td><td>'+esc(shortUrl(r.audio_url))+'</td><td>'+(r.vote===1?'👍':r.vote===-1?'👎':'—')+'</td><td style="max-width:250px">'+esc(r.text)+'</td><td>'+esc(r.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteCommentById('+r.id+')">🗑 删除</button></td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function deleteCommentById(id){
  if(!confirm('确认删除评论 #'+id+'？'))return;
  const r=await postJSON('/admin/api/comment/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');
  if(currentView==='comments')loadComments();
}

// ============ PLAYS ============
async function loadPlays(){
  $('viewTitle').textContent='🎧 播放记录';
  $('viewSub').textContent='所有播放日志，含 IP 和 UA';
  render('<div class="section"><div class="section-head"><h2>播放日志</h2><div class="h-actions"><button class="btn sm danger" onclick="clearPlays()">🗑 清空全部</button></div></div><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、歌曲、IP..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/plays');
  if(rows.error){toast(rows.error,'error');return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无播放记录</div>';return}
  let html='<table><thead><tr><th>ID</th><th>用户名</th><th>歌曲</th><th>IP</th><th>User-Agent</th><th>时间</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{html+='<tr><td>'+r.id+'</td><td style="font-weight:600">'+esc(r.username||'匿名')+'</td><td>'+esc(shortUrl(r.audio_url))+'</td><td>'+esc(r.ip||'-')+'</td><td style="max-width:200px;font-size:11px;color:var(--tx3)">'+esc(r.user_agent||'-')+'</td><td>'+esc(r.played_at)+'</td><td><button class="btn sm danger icon" onclick="deletePlayById('+r.id+')">🗑</button></td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function deletePlayById(id){
  const r=await postJSON('/admin/api/play/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');
  if(currentView==='plays')loadPlays();
}
async function clearPlays(){
  if(!confirm('⚠️ 确认清空所有播放日志？此操作不可撤销！'))return;
  if(!confirm('再次确认：真的要清空全部播放日志吗？'))return;
  const r=await postJSON('/admin/api/plays/clear',{});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已清空','success');loadPlays();
}

// ============ MESSAGES ============
async function loadMessages(){
  $('viewTitle').textContent='✉️ 私信监控';
  $('viewSub').textContent='所有用户之间的私信，上帝视角';
  render('<div class="section"><div class="search-bar"><input id="searchInput" placeholder="搜索发送者、接收者、内容..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/messages');
  if(rows.error){toast(rows.error,'error');return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无私信</div>';return}
  let html='<table><thead><tr><th>ID</th><th>发送者</th><th>接收者</th><th>内容</th><th>已读</th><th>时间</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{html+='<tr><td>'+r.id+'</td><td style="font-weight:600">'+esc(r.sender)+'</td><td style="font-weight:600">'+esc(r.receiver)+'</td><td style="max-width:280px">'+esc(r.text)+'</td><td>'+(r.read_flag?'<span class="badge green">已读</span>':'<span class="badge gray">未读</span>')+'</td><td>'+esc(r.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteMessageById('+r.id+')">🗑</button></td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function deleteMessageById(id){
  if(!confirm('确认删除私信 #'+id+'？'))return;
  const r=await postJSON('/admin/api/message/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');loadMessages();
}

// ============ SYSTEM LOGS ============
async function loadLogs(){
  $('viewTitle').textContent='📜 系统日志';
  $('viewSub').textContent='所有操作记录，系统的心跳';
  render('<div class="section"><div class="section-head"><h2>系统日志</h2><div class="h-actions"><button class="btn sm danger" onclick="clearLogs()">🗑 清空全部</button></div></div><div class="search-bar"><input id="searchInput" placeholder="搜索动作、目标、详情..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/logs');
  if(rows.error){toast(rows.error,'error');return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无日志</div>';return}
  let html='<table><thead><tr><th>ID</th><th>级别</th><th>动作</th><th>目标</th><th>详情</th><th>IP</th><th>时间</th><th>操作</th></tr></thead><tbody>';
  rows.forEach(r=>{
    const levelBadge=r.level==='WARN'?'<span class="badge yellow">WARN</span>':r.level==='ERROR'?'<span class="badge red">ERROR</span>':'<span class="badge blue">INFO</span>';
    html+='<tr><td>'+r.id+'</td><td>'+levelBadge+'</td><td style="font-weight:600">'+esc(r.action)+'</td><td>'+esc(r.target)+'</td><td style="max-width:250px">'+esc(r.detail)+'</td><td>'+esc(r.ip)+'</td><td>'+esc(r.created_at)+'</td><td><button class="btn sm danger icon" onclick="deleteLogById('+r.id+')">🗑</button></td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function deleteLogById(id){
  const r=await postJSON('/admin/api/log/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');loadLogs();
}
async function clearLogs(){
  if(!confirm('确认清空所有系统日志？'))return;
  const r=await postJSON('/admin/api/logs/clear',{});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已清空','success');loadLogs();
}

// ============ LOGIN LOGS ============
async function loadLoginLogs(){
  $('viewTitle').textContent='🔐 登录日志';
  $('viewSub').textContent='所有登录尝试，成功与失败';
  render('<div class="section"><div class="section-head"><h2>登录日志</h2><div class="h-actions"><button class="btn sm danger" onclick="clearLoginLogs()">🗑 清空全部</button></div></div><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、IP..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/login-logs');
  if(rows.error){toast(rows.error,'error');return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无登录日志</div>';return}
  let html='<table><thead><tr><th>ID</th><th>用户名</th><th>结果</th><th>IP</th><th>User-Agent</th><th>时间</th></tr></thead><tbody>';
  rows.forEach(r=>{html+='<tr><td>'+r.id+'</td><td style="font-weight:600">'+esc(r.username||'-')+'</td><td>'+(r.success?'<span class="badge green">成功</span>':'<span class="badge red">失败</span>')+'</td><td>'+esc(r.ip)+'</td><td style="max-width:220px;font-size:11px;color:var(--tx3)">'+esc(r.user_agent||'-')+'</td><td>'+esc(r.created_at)+'</td></tr>'});
  html+='</tbody></table>';
  $('tableWrap').innerHTML=html;
}
async function clearLoginLogs(){
  if(!confirm('确认清空所有登录日志？'))return;
  const r=await postJSON('/admin/api/login-logs/clear',{});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已清空','success');loadLoginLogs();
}

// ============ ACTIVITY ============
async function loadActivity(){
  $('viewTitle').textContent='⚡ 实时活动';
  $('viewSub').textContent='最近 50 条活动流';
  render('<div class="section"><div class="section-head"><h2>实时活动流</h2><div class="h-actions"><button class="btn sm primary" onclick="loadActivity()">🔄 刷新</button></div></div><div id="activityList"><div class="empty">加载中...</div></div></div>');
  const o=await fetchJSON('/admin/api/overview');
  if(o.error){toast(o.error,'error');return}
  const list=$('activityList');
  if(!o.recentActivity||o.recentActivity.length===0){list.innerHTML='<div class="empty">暂无活动</div>';return}
  list.innerHTML=o.recentActivity.map(a=>{
    const icon=a.type==='评分'?'👍':a.type==='评论'?'💬':'✉️';
    const color=a.type==='评分'?'green':a.type==='评论'?'blue':'purple';
    return '<div class="activity-item">'+
      '<div class="activity-icon" style="background:rgba(168,85,247,0.1)">'+icon+'</div>'+
      '<span class="badge '+color+'">'+a.type+'</span>'+
      '<span style="font-weight:600">'+esc(a.username)+'</span>'+
      '<span style="color:var(--tx3);font-size:11.5px">'+esc(shortUrl(a.audio_url))+'</span>'+
      (a.vote===1?'<span class="badge green">👍</span>':a.vote===-1?'<span class="badge red">👎</span>':'')+
      '<span style="margin-left:auto;color:var(--tx4);font-size:11px">'+esc(a.time)+'</span>'+
    '</div>';
  }).join('');
}

// ============ FEEDBACK (反馈管理) ============
async function loadFeedback(){
  $('viewTitle').textContent='📮 反馈管理';
  $('viewSub').textContent='用户反馈 · 查看并回复';
  render('<div class="section"><div class="section-head"><h2>📋 所有用户反馈</h2><div class="h-actions"><button class="btn sm" onclick="loadFeedback()">🔄 刷新</button></div></div><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、内容..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/feedback');
  if(rows.error){$('tableWrap').innerHTML='<div class="empty">'+rows.error+'</div>';return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无反馈</div>';return}
  let html='<div style="display:flex;flex-direction:column;gap:12px">';
  rows.forEach(r=>{
    const hasAtt=r.attachment_data?'📎 <a href="'+esc(r.attachment_data)+'" download="'+esc(r.attachment_name||'file')+'" style="color:#c084fc">'+esc(r.attachment_name||'附件')+'</a>':'';
    const replyHtml=r.admin_reply?
      '<div style="margin-top:8px;padding:8px 12px;background:rgba(34,197,94,0.08);border-radius:8px;border-left:3px solid #4ade80"><b style="color:#4ade80">管理员回复：</b>'+esc(r.admin_reply)+'<br><span style="font-size:10px;color:var(--tx4)">'+esc(r.replied_at||'')+'</span></div>':
      '<div style="margin-top:8px"><input id="replyInput_'+r.id+'" placeholder="输入回复..." style="width:70%;padding:6px 10px;border-radius:6px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx);font-size:12px"><button class="btn sm primary" onclick="replyFeedback('+r.id+')">📤 回复</button> <button class="btn sm danger" onclick="deleteFeedback('+r.id+')">🗑 删除</button></div>';
    html+='<div style="background:var(--bg3);padding:14px;border-radius:10px;border:1px solid var(--bd)">'+
      '<div style="display:flex;justify-content:space-between;margin-bottom:6px"><b style="color:#c084fc">'+esc(r.username)+'</b><span style="font-size:10px;color:var(--tx4)">'+esc(r.created_at)+' · IP: '+esc(r.ip||'-')+'</span></div>'+
      '<div style="font-size:13px;color:var(--tx);line-height:1.6">'+esc(r.message)+'</div>'+
      (hasAtt?'<div style="margin-top:6px;font-size:12px">'+hasAtt+'</div>':'')+
      replyHtml+
    '</div>';
  });
  html+='</div>';
  $('tableWrap').innerHTML=html;
}
async function replyFeedback(id){
  const inp=$('replyInput_'+id);if(!inp)return;
  const reply=inp.value.trim();if(!reply){toast('请输入回复内容','error');return}
  const r=await postJSON('/admin/api/feedback/reply',{id,reply});
  if(r.error){toast(r.error,'error');return}
  toast('✅ 回复成功','success');loadFeedback();
}
async function deleteFeedback(id){
  if(!confirm('确认删除此反馈？'))return;
  const r=await postJSON('/admin/api/feedback/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');loadFeedback();
}

// ============ COMMUNITY (社区管理) ============
async function loadCommunity(){
  $('viewTitle').textContent='🌐 社区管理';
  $('viewSub').textContent='社区帖子 · 查看与删除';
  render('<div class="section"><div class="section-head"><h2>📋 所有社区帖子</h2><div class="h-actions"><button class="btn sm" onclick="loadCommunity()">🔄 刷新</button></div></div><div class="search-bar"><input id="searchInput" placeholder="搜索用户名、内容..." oninput="filterTable()"></div><div class="table-wrap" id="tableWrap"><div class="empty">加载中...</div></div></div>');
  const rows=await fetchJSON('/admin/api/community');
  if(rows.error){$('tableWrap').innerHTML='<div class="empty">'+rows.error+'</div>';return}
  if(rows.length===0){$('tableWrap').innerHTML='<div class="empty">暂无帖子</div>';return}
  let html='<div style="display:flex;flex-direction:column;gap:12px">';
  rows.forEach(r=>{
    const hasAtt=r.attachment_data?
      (r.attachment_type&&r.attachment_type.startsWith('image')?
        '<img src="'+esc(r.attachment_data)+'" style="max-width:300px;max-height:200px;border-radius:8px;margin-top:6px;cursor:pointer" onclick="window.open(this.src)" />':
        '📎 <a href="'+esc(r.attachment_data)+'" download="'+esc(r.attachment_name||'file')+'" style="color:#c084fc">'+esc(r.attachment_name||'附件')+'</a>'):'';
    html+='<div style="background:var(--bg3);padding:14px;border-radius:10px;border:1px solid var(--bd)" id="post_'+r.id+'">'+
      '<div style="display:flex;justify-content:space-between;margin-bottom:6px"><b style="color:#c084fc">'+esc(r.username)+'</b><div><span style="font-size:10px;color:var(--tx4)">'+esc(r.created_at)+'</span> <button class="btn sm danger" onclick="deleteCommunityPost('+r.id+')">🗑 删除</button></div></div>'+
      '<div style="font-size:13px;color:var(--tx);line-height:1.6">'+esc(r.content)+'</div>'+
      (hasAtt?'<div style="margin-top:6px">'+hasAtt+'</div>':'')+
    '</div>';
  });
  html+='</div>';
  $('tableWrap').innerHTML=html;
}
async function deleteCommunityPost(id){
  if(!confirm('确认删除此帖子？'))return;
  const r=await postJSON('/admin/api/community/delete',{id});
  if(r.error){toast(r.error,'error');return}
  toast('🗑 已删除','success');loadCommunity();
}

// ============ COMMON ============
function filterTable(){
  const q=($('searchInput')||{}).value;
  if(!q){document.querySelectorAll('tr').forEach(tr=>tr.style.display='');return}
  const ql=q.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(tr=>{
    tr.style.display=tr.textContent.toLowerCase().includes(ql)?'':'none';
  });
}
function switchView(view){
  currentView=view;
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.view===view));
  document.getElementById('sidebar').classList.remove('open');
  const map={dashboard:loadDashboard,users:loadUsers,ratings:loadRatings,comments:loadComments,plays:loadPlays,messages:loadMessages,logs:loadLogs,loginLogs:loadLoginLogs,feedback:loadFeedback,community:loadCommunity,activity:loadActivity};
  if(map[view])map[view]();
}
function openModal(){$('modalOverlay').classList.add('open')}
function closeModal(){$('modalOverlay').classList.remove('open')}
async function exportJSON(){
  const data=await fetchJSON('/admin/api/export');
  if(data.error){toast(data.error,'error');return}
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='ncs-full-export-'+new Date().toISOString().slice(0,10)+'.json';a.click();
  toast('⬇ 已导出','success');
}
async function loadOverviewCounts(){
  const o=await fetchJSON('/admin/api/overview');
  if(o.error)return;
  $('cntUsers').textContent=o.totalUsers||0;
  $('cntRatings').textContent=o.totalRatings||0;
  $('cntComments').textContent=o.totalComments||0;
  $('cntPlays').textContent=o.totalPlays||0;
  $('cntMsgs').textContent=o.totalMessages||0;
  $('cntLogs').textContent=o.totalLogs||0;
  $('cntLogin').textContent=o.totalLoginLogs||0;
}
async function loadAll(){
  await switchView(currentView);
  loadOverviewCounts();
}

// Close modal on overlay click
$('modalOverlay').addEventListener('click',e=>{if(e.target===$('modalOverlay'))closeModal()});
// ESC to close modal
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});
// Init
loadAll();
setInterval(()=>{if(currentView==='dashboard'||currentView==='activity')loadAll()},30000);
</script>
</body>
</html>`;

// ============ STATIC FILE HELPERS ============
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
};
function serveStatic(req, res, filePath, ext) {
  fs.readFile(filePath, function (err, data) {
    if (err) { sendJSON(res, { error: 'Not found', path: req.url }, 404); return; }
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': Buffer.byteLength(data),
      'Access-Control-Allow-Origin': '*',
    };
    if (ext === '.json') headers['Cache-Control'] = 'public, max-age=300, stale-while-revalidate=3600';
    if (ext === '.html') headers['Cache-Control'] = 'public, max-age=0, must-revalidate';
    res.writeHead(200, headers);
    res.end(data);
  });
}

// ============ HTTP SERVER (for local dev) ============
const server = http.createServer(function (req, res) {
  // 本地开发：静态文件由 serverListener 之前的拦截处理
  const parsedUrl = url.parse(req.url, true);
  const p = parsedUrl.pathname;
  const m = req.method;

  if (m === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    res.end();
    return;
  }

  // 静态文件（仅本地开发需要，Vercel 由 CDN 直接服务静态文件）
  if (p === '/' || p === '/index.html') {
    return serveStatic(req, res, path.join(__dirname, 'index.html'), '.html');
  }
  if (p === '/catalog.json') {
    return serveStatic(req, res, path.join(__dirname, 'catalog.json'), '.json');
  }
  const ext = path.extname(p);
  if (ext && MIME[ext] && p !== '/admin') {
    const safePath = path.join(__dirname, p.split('/').filter(Boolean).join(path.sep));
    if (safePath.startsWith(__dirname) && fs.existsSync(safePath)) {
      return serveStatic(req, res, safePath, ext);
    }
  }

  // 其他所有请求交给 serverListener（API + Admin）
  ensureDB().then(() => serverListener(req, res)).catch(err => {
    try { sendJSON(res, { error: 'DB init failed: ' + (err && err.message || err) }, 500); }
    catch (e) {}
  });
});

// ============ EXPORT HANDLER (for Vercel serverless) ============
// 确保 DB 初始化只执行一次（Vercel 冷启动时复用全局缓存）
let _dbReady = null;
function ensureDB() {
  if (!_dbReady) {
    _dbReady = initDB().catch(function (err) {
      _dbReady = null;
      throw err;
    });
  }
  return _dbReady;
}

// 导出 Vercel 兼容的请求处理函数
async function handler(req, res) {
  try {
    await ensureDB();
    await serverListener(req, res);
  } catch (err) {
    try {
      sendJSON(res, { error: '服务器内部错误: ' + (err && err.message || err) }, 500);
    } catch (e) { /* response already sent */ }
  }
}
module.exports = handler;
module.exports.handler = handler;
module.exports.ensureDB = ensureDB;

// 把原来的 server 回调提取出来，供 Vercel handler 复用
const serverListener = async function (req, res) {
  try {
    const parsedUrl = url.parse(req.url, true);
    let p = parsedUrl.pathname;
    const m = req.method;
    // Netlify Function 路径规范化兜底：如果当前 URL 以 /.netlify/functions 开头，去掉前缀
    const NF_PREFIX = '/.netlify/functions/api';
    if (p.startsWith(NF_PREFIX)) {
      p = p.slice(NF_PREFIX.length) || '/';
      if (!p.startsWith('/')) p = '/' + p;
    }

    // CORS preflight
    if (m === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
      res.end();
      return;
    }

    // --- Public API Routes ---
    if (p === '/api/health') return await apiHealth(req, res);
    if (p === '/api/daily-info' && m === 'GET') return await apiDailyInfo(req, res);
    if (p === '/api/captcha' && m === 'GET') return await apiCaptcha(req, res);
    if (p === '/api/send-code' && m === 'POST') return await apiSendCode(req, res);
    if (p === '/api/register' && m === 'POST') return await apiRegister(req, res);
    if (p === '/api/login' && m === 'POST') return await apiLogin(req, res);
    if (p === '/api/rate' && m === 'POST') return await apiRate(req, res);
    if (p === '/api/comment' && m === 'POST') return await apiComment(req, res);
    if (p === '/api/play' && m === 'POST') return await apiPlay(req, res);
    if (p === '/api/message' && m === 'POST') return await apiSendMessage(req, res);
    if (p === '/api/messages' && m === 'GET') return await apiGetMessages(req, res);
    if (p === '/api/all' && m === 'GET') return await apiGetAll(req, res);
    if (p === '/api/song' && m === 'GET') return await apiGetSong(req, res);
    if (p === '/api/stats' && m === 'GET') return await apiStats(req, res);
    if (p === '/api/sync' && m === 'POST') return await apiSync(req, res);

    // --- 用户端：反馈 API ---
    if (p === '/api/feedback' && m === 'POST') return await apiSubmitFeedback(req, res);
    if (p === '/api/feedback' && m === 'GET') return await apiGetFeedback(req, res);

    // --- 用户端：社区 API ---
    if (p === '/api/community/post' && m === 'POST') return await apiCommunityPost(req, res);
    if (p === '/api/community/posts' && m === 'GET') return await apiCommunityList(req, res);

    // --- Admin: Dashboard Page ---
    if (p === '/admin' || p === '/admin/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(ADMIN_HTML);
      return;
    }

    // --- Admin: API Routes (GET) ---
    if (p === '/admin/api/overview' && m === 'GET') return await adminOverview(req, res);
    if (p === '/admin/api/users' && m === 'GET') return await adminUsers(req, res);
    if (p === '/admin/api/user/detail' && m === 'GET') return await adminUserDetail(req, res);
    if (p === '/admin/api/ratings' && m === 'GET') return await adminRatings(req, res);
    if (p === '/admin/api/comments' && m === 'GET') return await adminComments(req, res);
    if (p === '/admin/api/plays' && m === 'GET') return await adminPlays(req, res);
    if (p === '/admin/api/messages' && m === 'GET') return await adminMessages(req, res);
    if (p === '/admin/api/logs' && m === 'GET') return await adminLogs(req, res);
    if (p === '/admin/api/login-logs' && m === 'GET') return await adminLoginLogs(req, res);
    if (p === '/admin/api/export' && m === 'GET') return await adminExport(req, res);

    // --- Admin: API Routes (POST) ---
    if (p === '/admin/api/user/delete' && m === 'POST') return await adminDeleteUser(req, res);
    if (p === '/admin/api/user/password' && m === 'POST') return await adminChangePassword(req, res);
    if (p === '/admin/api/user/ban' && m === 'POST') return await adminToggleBan(req, res);
    if (p === '/admin/api/user/avatar' && m === 'POST') return await adminResetAvatar(req, res);
    if (p === '/admin/api/rating/delete' && m === 'POST') return await adminDeleteRating(req, res);
    if (p === '/admin/api/comment/delete' && m === 'POST') return await adminDeleteComment(req, res);
    if (p === '/admin/api/play/delete' && m === 'POST') return await adminDeletePlay(req, res);
    if (p === '/admin/api/plays/clear' && m === 'POST') return await adminClearPlays(req, res);
    if (p === '/admin/api/message/delete' && m === 'POST') return await adminDeleteMessage(req, res);
    if (p === '/admin/api/log/delete' && m === 'POST') return await adminDeleteLog(req, res);
    if (p === '/admin/api/logs/clear' && m === 'POST') return await adminClearLogs(req, res);
    if (p === '/admin/api/login-logs/clear' && m === 'POST') return await adminClearLoginLogs(req, res);

    // --- 管理员：反馈管理 API ---
    if (p === '/admin/api/feedback' && m === 'GET') return await adminGetFeedback(req, res);
    if (p === '/admin/api/feedback/reply' && m === 'POST') return await adminReplyFeedback(req, res);
    if (p === '/admin/api/feedback/delete' && m === 'POST') return await adminDeleteFeedback(req, res);

    // --- 管理员：社区管理 API ---
    if (p === '/admin/api/community' && m === 'GET') return await adminGetCommunity(req, res);
    if (p === '/admin/api/community/delete' && m === 'POST') return await adminDeleteCommunity(req, res);

    // 404
    sendJSON(res, { error: 'Not found', path: p }, 404);
  } catch (err) {
    try { sendJSON(res, { error: '服务器内部错误: ' + (err && err.message || err) }, 500); }
    catch (e) { /* response already sent */ }
  }
};

// ============ STARTUP (await DB init before listening) ============
// 仅在直接运行时启动 HTTP 服务器（Vercel 环境不执行此分支）
if (require.main === module) {
  initDB().then(function () {
    server.listen(PORT, '0.0.0.0', function () {
      console.log('');
      console.log('  =================================================');
      console.log('   NCS Ratings · Cloud Server (Turso/libSQL · God Mode Admin)');
      console.log('  =================================================');
      console.log('   用户网站 (User Site):   http://localhost:' + PORT + '/');
      console.log('   超级后台 (Admin Site):  http://localhost:' + PORT + '/admin');
      console.log('   API 健康检查:           http://localhost:' + PORT + '/api/health');
      console.log('   数据库 (Turso):         ' + TURSO_URL);
      console.log('  =================================================');
      console.log('');
      logSystem('INFO', 'SERVER_START', '-', '服务器启动，端口 ' + PORT, '127.0.0.1');
    });
  }).catch(function (err) {
    console.error('数据库初始化失败:', err && err.message || err);
    process.exit(1);
  });
}
