import express, { Request, Response } from 'express';
import path from 'path';
import { promises as fs, createReadStream } from 'fs';

const app = express();
const PORT = process.env.PORT || 3000;
const IMG_CODES_DIR = path.join(process.cwd(), 'images');

const MIME_TYPES: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

/**
 * Sanitizes a filename to be safe for storage and URL usage.
 * Replicates the functionality of Python's werkzeug.utils.secure_filename.
 * @param filename The filename to sanitize.
 * @returns A sanitized filename.
 */
const secureFilename = (filename: string): string => {
    // Normalize to NFD Unicode form to separate accents from letters,
    // then remove the accent characters.
    const withoutAccents = filename.normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    // Replace whitespace with underscores and remove characters that are not
    // alphanumeric, underscores, hyphens, or dots.
    const sanitized = withoutAccents
        .replace(/\s+/g, '_')
        .replace(/[^a-zA-Z0-9._-]/g, '');

    // Remove leading/trailing separators and ensure it's not just a dot.
    const final = sanitized.replace(/^[._-]+|[._-]+$/g, '');

    if (final === '.' || final === '..') {
        return '';
    }

    return final;
};

// Middleware to parse JSON requests - useful for potential future API endpoints
app.use(express.json());

// Serve static files from images directory
app.get('/:filename', async (req: Request, res: Response) => {
  const unsafeFilename = req.params.filename;
  const filename = secureFilename(unsafeFilename);

  if (!filename) {
    res.status(400).send('Invalid filename');
    return;
  }

  const imagePath = path.join(IMG_CODES_DIR, filename);

  try {
    const stats = await fs.stat(imagePath);

    if (!stats.isFile()) {
      res.status(404).send('Image not found');
      return;
    }

    const ext = path.extname(filename).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    
    const fileStream = createReadStream(imagePath);
    fileStream.pipe(res);

    fileStream.on('error', (error) => {
        console.error('Stream error:', error);
        if (!res.headersSent) {
            res.status(500).send('Internal Server Error');
        }
    });

  } catch (error: any) {
    if (error.code === 'ENOENT') {
      res.status(404).send('Image not found');
    } else {
      console.error(`Error serving ${filename}:`, error);
      res.status(500).send('Internal Server Error');
    }
  }
});

// Health check and file list endpoint
app.get('/', async (req: Request, res: Response) => {
  try {
    const files = await fs.readdir(IMG_CODES_DIR);
    const imageFiles = files.filter(file => 
        Object.keys(MIME_TYPES).includes(path.extname(file).toLowerCase())
    );

    res.json({ 
      message: 'Images Server is running',
      availableImages: imageFiles,
      usage: 'GET /{filename} to retrieve an image.'
    });
  } catch (error) {
    console.error("Could not read images directory:", error);
    res.status(500).json({
        message: 'Image Server is running, but could not read image directory.',
        error: 'Could not list available images.'
    });
  }
});

// Start the server only if not in a test environment
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`Server-img v1.0.0 is running on http://localhost:${PORT}`);
        console.log(`Images are served from the '${IMG_CODES_DIR}' directory`);
    });
}

export default app;

