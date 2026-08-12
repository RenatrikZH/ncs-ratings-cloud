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

const { createClient } = require('@libsql/client');
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
  CREATE INDEX IF NOT EXISTS idx_ratings_audio ON ratings(audio_url);
  CREATE INDEX IF NOT EXISTS idx_comments_audio ON comments(audio_url);
  CREATE INDEX IF NOT EXISTS idx_playlogs_audio ON play_logs(audio_url);
  CREATE INDEX IF NOT EXISTS idx_ratings_user ON ratings(username);
  CREATE INDEX IF NOT EXISTS idx_comments_user ON comments(username);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
  CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver);
  CREATE INDEX IF NOT EXISTS idx_loginlogs_user ON login_logs(username);
  CREATE INDEX IF NOT EXISTS idx_syslogs_action ON system_logs(action);
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

// ============ 每日动态密码（邀请码）算法 ============
// 密钥 — 与离线查看器保持一致，改这里同时要改 __daily_code_viewer.html
const DAILY_CODE_SECRET = 'NCS-DAILY-CODE-SECRET-2026-v1-神级后台专属密钥';
const BASE32_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去掉 I O 0 1 易混字符

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

// 根据日期生成 16 位邀请码（格式 XXXX-XXXX-XXXX-XXXX）
function generateDailyCode(dateStr) {
  const hmac = crypto.createHmac('sha256', DAILY_CODE_SECRET);
  hmac.update(dateStr || getShanghaiDate());
  const hash = hmac.digest();
  // 取前 10 字节（80 bit）→ Base32 编码正好 16 字符
  let code = '';
  for (let i = 0; i < 10; i++) {
    const byte = hash[i];
    // 每个字节拆成 5 bit 组（前 2 组用本字节，第 3 组跨字节）
    // 但为了简单，我们对 10 字节做 80/5=16 次 5-bit 提取
  }
  // 重写：用位运算提取 16 组 5-bit
  let bitPos = 0;
  let byteIdx = 0;
  for (let i = 0; i < 16; i++) {
    let val = 0;
    for (let b = 0; b < 5; b++) {
      val <<= 1;
      const byte = hash[byteIdx];
      const bit = (byte >> (7 - bitPos)) & 1;
      val |= bit;
      bitPos++;
      if (bitPos >= 8) { bitPos = 0; byteIdx++; }
    }
    code += BASE32_CHARS[val & 31];
  }
  // 格式化为 XXXX-XXXX-XXXX-XXXX
  return code.slice(0, 4) + '-' + code.slice(4, 8) + '-' + code.slice(8, 12) + '-' + code.slice(12, 16);
}

// 校验邀请码（去除空格、连字符，不区分大小写）
function verifyDailyCode(input) {
  if (!input) return false;
  const clean = String(input).toUpperCase().replace(/[\s\-]/g, '');
  if (clean.length !== 16) return false;
  const todayCode = generateDailyCode().replace(/-/g, '');
  return clean === todayCode;
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

// 公开接口：返回今日日期（不返回密码，密码只能离线查看）
async function apiDailyInfo(req, res) {
  const date = getShanghaiDate();
  sendJSON(res, { date, hint: '请使用离线密码查看器获取今日邀请码，格式 XXXX-XXXX-XXXX-XXXX' });
}

async function apiRegister(req, res) {
  const { username, password, inviteCode } = await readBody(req);
  const ip = getIP(req);
  if (!username || !password) return sendJSON(res, { error: '用户名和密码不能为空' }, 400);
  if (username.length < 2) return sendJSON(res, { error: '用户名至少2个字符' }, 400);
  // 校验当日邀请码
  if (!verifyDailyCode(inviteCode)) {
    logSystem('WARN', 'REGISTER_CODE_FAIL', username, '邀请码错误或已过期', ip);
    return sendJSON(res, { error: '邀请码错误或已过期，请使用离线查看器获取当日最新密码' }, 403);
  }
  try {
    await db.execute({
      sql: 'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      args: [username, hashPwd(password)]
    });
    logSystem('INFO', 'REGISTER', username, '新用户注册（邀请码验证通过）', ip);
    sendJSON(res, { success: true, user: { name: username, joined: new Date().toISOString() } });
  } catch (e) {
    if (String(e).includes('UNIQUE')) {
      logSystem('WARN', 'REGISTER_DUPLICATE', username, '尝试注册已存在用户名', ip);
      sendJSON(res, { error: '用户名已存在' }, 409);
    }
    else sendJSON(res, { error: '注册失败' }, 500);
  }
}

async function apiLogin(req, res) {
  const { username, password } = await readBody(req);
  const ip = getIP(req);
  const ua = getUA(req);
  if (!username || !password) return sendJSON(res, { error: '用户名和密码不能为空' }, 400);

  // 检查是否被封禁
  const userResult = await db.execute({
    sql: 'SELECT banned FROM users WHERE username = ?',
    args: [username]
  });
  const userRow = userResult.rows[0];
  if (userRow && userRow.banned) {
    logLogin(username, 0, ip, ua);
    logSystem('WARN', 'LOGIN_BANNED', username, '被封禁用户尝试登录', ip);
    return sendJSON(res, { error: '账号已被封禁，请联系管理员' }, 403);
  }

  const loginResult = await db.execute({
    sql: 'SELECT username, created_at FROM users WHERE username = ? AND password_hash = ?',
    args: [username, hashPwd(password)]
  });
  const row = loginResult.rows[0];
  if (row) {
    await db.execute({
      sql: "UPDATE users SET last_login = datetime('now') WHERE username = ?",
      args: [username]
    });
    logLogin(username, 1, ip, ua);
    logSystem('INFO', 'LOGIN', username, '登录成功', ip);
    sendJSON(res, { success: true, user: { name: row.username, joined: row.created_at } });
  } else {
    logLogin(username, 0, ip, ua);
    logSystem('WARN', 'LOGIN_FAIL', username, '登录失败（密码错误或用户不存在）', ip);
    sendJSON(res, { error: '用户名或密码错误' }, 401);
  }
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

// ============ ADMIN DASHBOARD HTML ============
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCS Ratings · 超级管理后台</title>
<style>
:root{
  --bg:#08080a;--bg2:#131316;--bg3:#1a1a20;--bg4:#222230;--bg5:#2a2a35;
  --tx:#f4f4f5;--tx2:#d4d4d8;--tx3:#a1a1aa;--tx4:#71717a;
  --accent:#22c55e;--accent2:#3b82f6;--red:#ef4444;--yellow:#f59e0b;--purple:#a855f7;--cyan:#06b6d4;
  --bd:rgba(255,255,255,0.08);--bd2:rgba(255,255,255,0.14);--radius:12px;
  --shadow:0 10px 30px -10px rgba(0,0,0,0.6);
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:var(--bg);color:var(--tx);font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;font-size:13.5px;line-height:1.5;background-image:radial-gradient(1000px 500px at 90% -10%,rgba(34,197,94,0.05),transparent 60%),radial-gradient(800px 400px at -10% 30%,rgba(59,130,246,0.04),transparent 60%);background-attachment:fixed}
a{color:var(--accent2);text-decoration:none;cursor:pointer}
button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit}
input,select,textarea{font-family:inherit;font-size:inherit;color:inherit;background:transparent;border:none;outline:none}

/* Layout */
.app{display:grid;grid-template-columns:240px 1fr;height:100vh;height:100dvh}
.sidebar{background:linear-gradient(180deg,#08080a,#0c0c0f);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;position:fixed;width:240px;height:100vh;height:100dvh;left:0;top:0;z-index:20}
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

.main{margin-left:240px;display:flex;flex-direction:column;height:100vh;height:100dvh;overflow:hidden}
.topbar{height:60px;padding:0 28px;display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--bd);background:rgba(8,8,10,0.85);backdrop-filter:blur(14px);position:sticky;top:0;z-index:10;flex-shrink:0}
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
@media(max-width:1024px){
  .app{grid-template-columns:1fr}
  .sidebar{transform:translateX(-100%);transition:transform .25s}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .menu-toggle{display:flex !important}
}
.menu-toggle{display:none;width:34px;height:34px;border-radius:8px;align-items:center;justify-content:center;font-size:18px;background:var(--bg3);border:1px solid var(--bd)}
@media(max-width:768px){
  .content{padding:16px}
  .topbar{padding:0 16px}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .search-bar{padding:10px 14px}
  td,th{padding:8px 10px;font-size:11.5px}
}
</style>
</head>
<body>
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
  const map={dashboard:loadDashboard,users:loadUsers,ratings:loadRatings,comments:loadComments,plays:loadPlays,messages:loadMessages,logs:loadLogs,loginLogs:loadLoginLogs,activity:loadActivity};
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

// ============ HTTP SERVER ============
const server = http.createServer(async function (req, res) {
  try {
    const parsedUrl = url.parse(req.url, true);
    const p = parsedUrl.pathname;
    const m = req.method;

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

    // --- Admin: API Routes (POST - 管理 操作) ---
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

    // --- Static: User Frontend ---
    if (p === '/' || p === '/index.html') {
      return serveStatic(req, res, path.join(__dirname, 'index.html'), '.html');
    }
    if (p === '/catalog.json') {
      return serveStatic(req, res, path.join(__dirname, 'catalog.json'), '.json');
    }
    // Catch-all for any other static requests
    const ext = path.extname(p);
    if (ext && MIME[ext]) {
      const safePath = path.join(__dirname, p.split('/').filter(Boolean).join(path.sep));
      if (safePath.startsWith(__dirname) && fs.existsSync(safePath)) {
        return serveStatic(req, res, safePath, ext);
      }
    }
    // Fallback to index.html for SPA
    return serveStatic(req, res, path.join(__dirname, 'index.html'), '.html');
  } catch (err) {
    try { sendJSON(res, { error: '服务器内部错误: ' + (err && err.message || err) }, 500); }
    catch (e) { /* response already sent */ }
  }
});

// ============ STARTUP (await DB init before listening) ============
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
    // 启动时记录系统日志
    logSystem('INFO', 'SERVER_START', '-', '服务器启动，端口 ' + PORT, '127.0.0.1');
  });
}).catch(function (err) {
  console.error('数据库初始化失败:', err && err.message || err);
  process.exit(1);
});
