const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises; // lebih baik pakai promises
const { body, validationResult } = require('express-validator'); // tambahan

const app = express();
const PORT = process.env.PORT || 3000;

// =============================================
//              SETUP DIRECTORY
// =============================================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// =============================================
//              DATABASE
// =============================================
const db = new sqlite3.Database('./anime_list.db', (err) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

  db.run(`
    CREATE TABLE IF NOT EXISTS anime (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      rating INTEGER CHECK(rating >= 1 AND rating <= 10),
      episodes INTEGER,
      genre TEXT,
      image_path TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
});

// =============================================
//              MULTER SETUP
// =============================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/i;
    const extOk = allowed.test(path.extname(file.originalname).toLowerCase());
    const mimeOk = allowed.test(file.mimetype);
    cb(null, extOk && mimeOk);
  }
}).single('image');

// =============================================
//              MIDDLEWARE
// =============================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/uploads', express.static(uploadDir));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SESSION_SECRET || 'anime-secret-key-ganti-yang-aman!!!',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Middleware untuk membuat flash message mudah
app.use((req, res, next) => {
  res.locals.error = req.query.error || null;
  res.locals.success = req.query.success || null;
  res.locals.user = req.session.userId ? { username: req.session.username } : null;
  next();
});

// Auth check
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();
  res.redirect('/login');
};

// =============================================
//              ROUTES
// =============================================

app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/dashboard' : '/login');
});

// REGISTER
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', [
  body('username').trim().isLength({ min: 3, max: 30 }).escape(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('register', { error: errors.array()[0].msg });
  }

  const { username, password } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    await new Promise((resolve, reject) => {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashed], 
        function(err) {
          if (err) return reject(err);
          resolve();
        });
    });

    res.redirect('/login?success=Registrasi berhasil, silakan login');
  } catch (err) {
    console.error(err);
    let msg = 'Terjadi kesalahan server';
    if (err.message?.includes('UNIQUE')) msg = 'Username sudah digunakan';
    res.render('register', { error: msg });
  }
});

// LOGIN
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Username atau password salah' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Terjadi kesalahan server' });
  }
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// DASHBOARD
app.get('/dashboard', isAuthenticated, (req, res) => {
  db.all(
    'SELECT * FROM anime WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.userId],
    (err, animeList) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Database error');
      }
      res.render('dashboard', { 
        username: req.session.username, 
        animeList 
      });
    }
  );
});

// ADD ANIME
app.post('/anime/add', isAuthenticated, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.log("Upload error:", err);
      return res.redirect('/dashboard?error=' + encodeURIComponent(err.message));
    }

    let { title, rating, episodes, genre } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    // Bersihkan & konversi
    title = (title || '').trim();
    rating = Number(rating);
    episodes = episodes ? Number(episodes) : null;     // kalau kosong → null
    genre   = (genre || '').trim() || null;            // kalau kosong → null

    if (!title || isNaN(rating) || rating < 1 || rating > 10) {
      return res.redirect('/dashboard?error=Judul dan rating (1-10) wajib diisi!');
    }

    // Debug: lihat apa yang masuk
    console.log('Data yang mau disimpan:', {
      user_id: req.session.userId,
      title,
      rating,
      episodes,
      genre,
      imagePath
    });

    try {
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO anime (user_id, title, rating, episodes, genre, image_path)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [req.session.userId, title, rating, episodes, genre, imagePath],
          function(err) {
            if (err) return reject(err);
            resolve();
          }
        );
      });

      res.redirect('/dashboard?success=Anime berhasil ditambahkan!');
    } catch (err) {
      console.error('Insert error:', err);
      res.redirect('/dashboard?error=Gagal menyimpan anime');
    }
  });
});
// =============================================
//      EDIT & UPDATE (contoh lebih rapi)
// =============================================
app.get('/anime/edit/:id', isAuthenticated, (req, res) => {
  db.get(
    'SELECT * FROM anime WHERE id = ? AND user_id = ?',
    [req.params.id, req.session.userId],
    (err, anime) => {
      if (err || !anime) return res.redirect('/dashboard');
      res.render('edit', { anime, error: null });
    }
  );
});

app.post('/anime/update/:id', isAuthenticated, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.redirect(`/anime/edit/${req.params.id}?error=${err.message}`);
    }

    const { title, rating, episodes, genre } = req.body;
    const animeId = req.params.id;

    if (!title || !rating || rating < 1 || rating > 10) {
      return res.redirect(`/anime/edit/${animeId}?error=Judul & rating wajib (1-10)`);
    }

    try {
      const oldAnime = await new Promise((resolve) => {
        db.get('SELECT image_path FROM anime WHERE id = ? AND user_id = ?', 
          [animeId, req.session.userId], 
          (err, row) => resolve(row || {})
        );
      });

      let imagePath = oldAnime.image_path;

      if (req.file) {
        if (oldAnime.image_path) {
          await fs.unlink(path.join(uploadDir, oldAnime.image_path)).catch(() => {});
        }
        imagePath = req.file.filename;
      }

      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE anime SET title=?, rating=?, episodes=?, genre=?, image_path=? WHERE id=? AND user_id=?',
          [title.trim(), Number(rating), episodes || null, genre?.trim() || null, imagePath, animeId, req.session.userId],
          (err) => err ? reject(err) : resolve()
        );
      });

      res.redirect('/dashboard?success=Data berhasil diperbarui');
    } catch (err) {
      console.error(err);
      res.redirect(`/anime/edit/${animeId}?error=Gagal memperbarui`);
    }
  });
});

// DELETE
app.post('/anime/delete/:id', isAuthenticated, async (req, res) => {
  const animeId = req.params.id;

  try {
    const anime = await new Promise((resolve) => {
      db.get('SELECT image_path FROM anime WHERE id = ? AND user_id = ?', 
        [animeId, req.session.userId], 
        (err, row) => resolve(row)
      );
    });

    if (!anime) return res.redirect('/dashboard');

    if (anime.image_path) {
      await fs.unlink(path.join(uploadDir, anime.image_path)).catch(() => {});
    }

    await new Promise((resolve, reject) => {
      db.run('DELETE FROM anime WHERE id = ? AND user_id = ?', 
        [animeId, req.session.userId], 
        (err) => err ? reject(err) : resolve()
      );
    });

    res.redirect('/dashboard?success=Anime dihapus');
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard?error=Gagal menghapus');
  }
});

// 404 & Error handler
app.use((req, res) => {
  res.status(404).render('404'); // buat file 404.ejs kalau mau
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// =============================================
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
