const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Create uploads directory if not exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Database setup
const db = new sqlite3.Database('./anime_list.db', (err) => {
  if (err) console.error(err);
  else console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS anime (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    rating INTEGER CHECK(rating >= 1 AND rating <= 10),
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
});

// Multer config for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image files allowed!'));
  }
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'anime-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Auth middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Register page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('register', { error: 'Username dan password harus diisi!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
      [username, hashedPassword], 
      (err) => {
        if (err) {
          return res.render('register', { error: 'Username sudah dipakai!' });
        }
        res.redirect('/login');
      }
    );
  } catch (error) {
    res.render('register', { error: 'Terjadi kesalahan!' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'Username atau password salah!' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.render('login', { error: 'Username atau password salah!' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/dashboard');
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Dashboard - show all anime
app.get('/dashboard', isAuthenticated, (req, res) => {
  db.all('SELECT * FROM anime WHERE user_id = ? ORDER BY created_at DESC', 
    [req.session.userId], 
    (err, anime) => {
      if (err) {
        return res.status(500).send('Database error');
      }
      res.render('dashboard', { 
        username: req.session.username, 
        animeList: anime 
      });
    }
  );
});

// Add anime
app.post('/anime/add', isAuthenticated, upload.single('image'), (req, res) => {
  const { title, rating } = req.body;
  const imagePath = req.file ? req.file.filename : null;

  if (!title || !rating) {
    return res.redirect('/dashboard?error=Title dan rating harus diisi!');
  }

  db.run('INSERT INTO anime (user_id, title, rating, image_path) VALUES (?, ?, ?, ?)',
    [req.session.userId, title, rating, imagePath],
    (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/dashboard?error=Gagal menambahkan anime!');
      }
      res.redirect('/dashboard');
    }
  );
});

// Edit anime page
app.get('/anime/edit/:id', isAuthenticated, (req, res) => {
  db.get('SELECT * FROM anime WHERE id = ? AND user_id = ?', 
    [req.params.id, req.session.userId], 
    (err, anime) => {
      if (err || !anime) {
        return res.redirect('/dashboard');
      }
      res.render('edit', { anime });
    }
  );
});

// Update anime
app.post('/anime/update/:id', isAuthenticated, upload.single('image'), (req, res) => {
  const { title, rating } = req.body;
  const animeId = req.params.id;

  db.get('SELECT * FROM anime WHERE id = ? AND user_id = ?', 
    [animeId, req.session.userId], 
    (err, anime) => {
      if (err || !anime) {
        return res.redirect('/dashboard');
      }

      let imagePath = anime.image_path;
      
      if (req.file) {
        // Delete old image if exists
        if (anime.image_path) {
          fs.unlink(path.join('uploads', anime.image_path), () => {});
        }
        imagePath = req.file.filename;
      }

      db.run('UPDATE anime SET title = ?, rating = ?, image_path = ? WHERE id = ?',
        [title, rating, imagePath, animeId],
        (err) => {
          if (err) {
            console.error(err);
          }
          res.redirect('/dashboard');
        }
      );
    }
  );
});

// Delete anime
app.post('/anime/delete/:id', isAuthenticated, (req, res) => {
  db.get('SELECT * FROM anime WHERE id = ? AND user_id = ?', 
    [req.params.id, req.session.userId], 
    (err, anime) => {
      if (err || !anime) {
        return res.redirect('/dashboard');
      }

      // Delete image file
      if (anime.image_path) {
        fs.unlink(path.join('uploads', anime.image_path), () => {});
      }

      db.run('DELETE FROM anime WHERE id = ?', [req.params.id], (err) => {
        if (err) {
          console.error(err);
        }
        res.redirect('/dashboard');
      });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});