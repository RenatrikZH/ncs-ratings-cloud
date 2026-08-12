/**
 * Netlify Function — API Handler Adapter (deploy build: 20260812-v12-qq-smtp-working)
 * 将 Netlify 的 event/context 格式适配到 Node.js req/res 格式
 * 然后委托给 __db_server_cloud.cjs 的 serverListener 处理
 * 
 * 重要说明：此文件每修改一次，Netlify 才会重新 ZIP 打包 Function bundle。
 * 所以当 __db_server_cloud.cjs 有重大代码变更时，记得在此文件改版本戳。
 */
const { Readable } = require('stream');
const serverHandler = require('../../__db_server_cloud.cjs');

exports.handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  // 构建完整的 URL（含查询参数）
  // Netlify redirect 后路径可能是 /.netlify/functions/api 或 带 /api/xxx 后缀
  // 需要规范化为 serverListener 期望的格式：/admin 或 /api/xxx 或 /admin/api/xxx
  let path = event.path || '/';
  const FN_PREFIX = '/.netlify/functions/api';
  if (path.startsWith(FN_PREFIX)) {
    let rest = path.slice(FN_PREFIX.length);
    if (!rest.startsWith('/')) rest = '/' + rest;
    // 如果 redirect 规则没有保留原路径，则 rest 会是 '/'，
    // 此时尝试从 headers 中的 x-nf-request-path 获取原始请求路径
    if (rest === '/' || rest === '') {
      const origPath = (event.headers && (event.headers['x-nf-request-path'] || event.headers['X-Nf-Request-Path'])) || '';
      if (origPath) rest = origPath;
    }
    path = rest || '/';
  }
  // 安全兜底：如果路径完全是空的 Function root，尝试原始 http 路径
  const query = event.queryStringParameters || {};
  const queryString = Object.keys(query)
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(query[k])}`)
    .join('&');
  const url = queryString ? `${path}?${queryString}` : path;

  // 构建请求体
  const bodyBuffer = event.body
    ? Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8')
    : Buffer.alloc(0);

  // 创建模拟 req 对象（Readable stream 以支持 readBody 的 data/end 事件）
  const req = new Readable();
  req.url = url;
  req.method = event.httpMethod || 'GET';
  req.headers = event.headers || {};
  req.socket = {
    remoteAddress: (event.headers && event.headers['x-forwarded-for'] || '0.0.0.0')
      .split(',')[0].trim()
  };
  req.destroy = function() {};
  req.push(bodyBuffer);
  req.push(null);

  // 创建模拟 res 对象
  let statusCode = 200;
  let headers = {};
  let bodyParts = [];
  let responseEnded = false;

  const res = {
    writeHead: function(status, hdrs) {
      statusCode = status;
      if (hdrs) {
        if (Array.isArray(hdrs)) {
          // [key, value, key, value, ...] format
          for (let i = 0; i < hdrs.length; i += 2) {
            headers[hdrs[i]] = hdrs[i + 1];
          }
        } else {
          Object.assign(headers, hdrs);
        }
      }
    },
    write: function(chunk) {
      if (!responseEnded) {
        bodyParts.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      }
    },
    end: function(data) {
      if (data && !responseEnded) {
        bodyParts.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
      }
      responseEnded = true;
    },
    setHeader: function(key, value) { headers[key] = value; },
    getHeader: function(key) { return headers[key]; },
    flushHeaders: function() {},
  };

  // 调用服务器 handler
  try {
    await serverHandler(req, res);
  } catch (err) {
    statusCode = 500;
    headers = { 'Content-Type': 'application/json; charset=utf-8' };
    bodyParts = [Buffer.from(JSON.stringify({ error: err.message }))];
  }

  // 构建响应
  const body = Buffer.concat(bodyParts).toString('utf8');

  // 处理 multi-value headers (Netlify 不支持)
  const flatHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    flatHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
  }

  return {
    statusCode: statusCode,
    headers: flatHeaders,
    body: body,
  };
};
