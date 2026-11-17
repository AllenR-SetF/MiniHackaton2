'use strict';

// LOCAL DEVELOPMENT ONLY: serves this folder on http://localhost:5500 so the
// client runs on a different origin than the API (http://localhost:3000).
// In production the frontend is plain static files on a static host.

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 5500;
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

http.createServer((req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);
  if (!file.startsWith(__dirname) || !TYPES[path.extname(file)]) {
    res.writeHead(404).end('Not found');
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) return res.writeHead(404).end('Not found');
    res.writeHead(200, { 'Content-Type': `${TYPES[path.extname(file)]}; charset=utf-8`, 'Cache-Control': 'no-store' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`Frontend dev server: http://localhost:${PORT}`));
