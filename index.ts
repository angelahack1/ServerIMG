
import express, { Request, Response } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { promises as fs, createReadStream } from 'fs';
// import FileType from 'file-type'; // Removed static import

// ---------- Configuration ----------
const PORT = process.env.PORT || 3000;
const IMG_CODES_DIR = path.join(process.cwd(), 'images');
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico'];
const ALLOWED_MIME: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};
const HEALTH_TOKEN = process.env.HEALTH_TOKEN || 'change-me';
const HEALTH_IP_WHITELIST = (process.env.HEALTH_IP_WHITELIST || '').split(',').filter(Boolean);

// ---------- Simple logger ----------
enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
}
function log(level: LogLevel, message: string, meta?: unknown) {
  const ts = new Date().toISOString();
  if (meta) {
    console.log(`[${ts}] ${level}: ${message}`, meta);
  } else {
    console.log(`[${ts}] ${level}: ${message}`);
  }
}

// ---------- Security middlewares ----------
const app = express();
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'"],
        scriptSrc: ["'none'"],
        styleSrc: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
      },
    },
    // other helmet defaults (XSS‑Protection, HSTS, etc.) are kept
  })
);

// ---------- Helper: safe filename ----------
function getSafeFilePath(unsafeName: string): string | null {
  // Remove any path separators and normalize
  const sanitized = unsafeName.replace(/[\\\/]+/g, '');
  const ext = path.extname(sanitized).toLowerCase();

  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return null;
  }

  // Resolve against the base directory and ensure it stays inside
  const resolved = path.resolve(IMG_CODES_DIR, sanitized);
  if (!resolved.startsWith(IMG_CODES_DIR + path.sep)) {
    return null;
  }
  return resolved;
}

// ---------- Middleware: MIME validation ----------
async function validateMime(filePath: string, expectedExt: string): Promise<boolean> {
  try {
    // Dynamic import for ESM compatibility
    const { fileTypeFromFile } = await import('file-type');
    const type = await fileTypeFromFile(filePath);
    if (!type) {
      return false;
    }
    const expectedMime = ALLOWED_MIME[expectedExt];
    return type.mime === expectedMime;
  } catch (err) {
    log(LogLevel.WARN, 'MIME validation error', { filePath, error: err });
    return false;
  }
}

// ---------- Health‑check endpoint ----------
app.get('/', (req: Request, res: Response) => {
  // Token‑based protection (preferred)
  const token = req.query.token as string | undefined;
  if (HEALTH_TOKEN && token !== HEALTH_TOKEN) {
    // Optional IP whitelist fallback
    const clientIp = req.ip || '';
    if (!HEALTH_IP_WHITELIST.includes(clientIp)) {
      res.status(403).send('Forbidden');
      return;
    }
  }
  res.send('OK');
});

// ---------- Serve images ----------
app.get('/img/:filename', async (req: Request, res: Response) => {
  const unsafeName = req.params.filename;
  const safePath = getSafeFilePath(unsafeName);
  if (!safePath) {
    log(LogLevel.WARN, 'Invalid filename request', { unsafeName });
    res.status(400).send('Invalid filename');
    return;
  }

  const ext = path.extname(safePath).toLowerCase();

  // Verify the file exists
  try {
    await fs.access(safePath);
  } catch {
    log(LogLevel.WARN, 'File not found', { safePath });
    res.status(404).send('Image not found');
    return;
  }

  // MIME type validation against actual content
  const mimeOk = await validateMime(safePath, ext);
  if (!mimeOk) {
    log(LogLevel.WARN, 'MIME mismatch', { safePath, ext });
    res.status(415).send('Unsupported Media Type');
    return;
  }

  // Stream the file
  const stream = createReadStream(safePath);
  stream.on('open', () => {
    res.setHeader('Content-Type', ALLOWED_MIME[ext]);
    stream.pipe(res);
  });
  stream.on('error', (err) => {
    log(LogLevel.ERROR, 'Stream error', err);
    if (!res.headersSent) {
      res.status(500).send('Internal Server Error');
    }
  });
});

// ---------- Fallback for unknown routes ----------
app.use((_req, res) => {
  res.status(404).send('Not found');
});

// ---------- Start server ----------
app.listen(PORT, () => {
  // Note: TLS termination should be performed by an upstream proxy/ingress.
  log(LogLevel.INFO, `Server listening on port ${PORT}`);
});
