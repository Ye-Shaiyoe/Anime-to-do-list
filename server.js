const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

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
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    newsletter INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS anime (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    rating INTEGER CHECK(rating >= 1 AND rating <= 10),
    episodes INTEGER,
    genre TEXT,
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
app.use('/gmbr', express.static('gmbr'));
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

// ============= VALIDATION HELPERS =============

// Validate username
const validateUsername = (username) => {
  if (!username || username.length < 3) {
    return { valid: false, message: 'Username minimal 3 karakter' };
  }
  if (username.length > 20) {
    return { valid: false, message: 'Username maksimal 20 karakter' };
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, message: 'Username hanya boleh berisi huruf, angka, dan underscore' };
  }
  return { valid: true };
};

// Validate email
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return { valid: false, message: 'Format email tidak valid' };
  }
  return { valid: true };
};

// Validate password
const validatePassword = (password) => {
  if (!password || password.length < 8) {
    return { valid: false, message: 'Password minimal 8 karakter' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password harus mengandung huruf besar' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password harus mengandung huruf kecil' };
  }
  if (!/\d/.test(password)) {
    return { valid: false, message: 'Password harus mengandung angka' };
  }
  return { valid: true };
};

// ============= ROUTES =============

// Home
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
  const { username, email, password, confirmPassword, terms, newsletter } = req.body;

  // Validate all fields
  if (!username || !email || !password || !confirmPassword) {
    return res.render('register', { error: 'Semua field harus diisi!' });
  }

  // Validate terms
  if (!terms) {
    return res.render('register', { error: 'Anda harus menyetujui Syarat dan Ketentuan!' });
  }

  // Validate username
  const usernameValidation = validateUsername(username);
  if (!usernameValidation.valid) {
    return res.render('register', { error: usernameValidation.message });
  }

  // Validate email
  const emailValidation = validateEmail(email);
  if (!emailValidation.valid) {
    return res.render('register', { error: emailValidation.message });
  }

  // Validate password
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.render('register', { error: passwordValidation.message });
  }

  // Check password match
  if (password !== confirmPassword) {
    return res.render('register', { error: 'Password dan konfirmasi password tidak cocok!' });
  }

  try {
    // Check if username already exists
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, existingUser) => {
      if (existingUser) {
        return res.render('register', { error: 'Username sudah digunakan!' });
      }

      // Check if email already exists
      db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingEmail) => {
        if (existingEmail) {
          return res.render('register', { error: 'Email sudah terdaftar!' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const newsletterValue = newsletter ? 1 : 0;

        // Insert new user
        db.run('INSERT INTO users (username, email, password, newsletter) VALUES (?, ?, ?, ?)', 
          [username, email, hashedPassword, newsletterValue], 
          (err) => {
            if (err) {
              console.error(err);
              return res.render('register', { error: 'Terjadi kesalahan saat mendaftar!' });
            }
            
            // Redirect to login with success message
            res.redirect('/login?success=Registrasi berhasil! Silakan login.');
          }
        );
      });
    });
  } catch (error) {
    console.error(error);
    res.render('register', { error: 'Terjadi kesalahan server!' });
  }
});

// Login page
app.get('/login', (req, res) => {
  const success = req.query.success || null;
  res.render('login', { error: null, success });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('login', { error: 'Username dan password harus diisi!', success: null });
  }

  // Allow login with username or email
  const query = 'SELECT * FROM users WHERE username = ? OR email = ?';
  
  db.get(query, [username, username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Terjadi kesalahan!', success: null });
    }

    if (!user) {
      return res.render('login', { error: 'Username/email atau password salah!', success: null });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.render('login', { error: 'Username/email atau password salah!', success: null });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.email = user.email;
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
        console.error(err);
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
  const { title, rating, episodes, genre } = req.body;
  const imagePath = req.file ? req.file.filename : null;

  if (!title || !rating) {
    return res.redirect('/dashboard?error=Title dan rating harus diisi!');
  }

  db.run('INSERT INTO anime (user_id, title, rating, episodes, genre, image_path) VALUES (?, ?, ?, ?, ?, ?)',
    [req.session.userId, title, rating, episodes || null, genre || null, imagePath],
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
  const { title, rating, episodes, genre } = req.body;
  const animeId = req.params.id;

  db.get('SELECT * FROM anime WHERE id = ? AND user_id = ?', 
    [animeId, req.session.userId], 
    (err, anime) => {
      if (err || !anime) {
        return res.redirect('/dashboard');
      }

      let imagePath = anime.image_path;
      
      // Update image if new file uploaded
      if (req.file) {
        // Delete old image
        if (anime.image_path) {
          fs.unlink(path.join('uploads', anime.image_path), () => {});
        }
        imagePath = req.file.filename;
      }

      // Update database
      db.run('UPDATE anime SET title = ?, rating = ?, episodes = ?, genre = ?, image_path = ? WHERE id = ?',
        [title, rating, episodes || null, genre || null, imagePath, animeId],
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

      // Delete image file if exists
      if (anime.image_path) {
        fs.unlink(path.join('uploads', anime.image_path), () => {});
      }

      // Delete from database
      db.run('DELETE FROM anime WHERE id = ?', [req.params.id], (err) => {
        if (err) {
          console.error(err);
        }
        res.redirect('/dashboard');
      });
    }
  );
});

// Terms page (placeholder)
app.get('/terms', (req, res) => {
  res.send('<h1>Syarat dan Ketentuan</h1><p>Halaman Syarat dan Ketentuan</p>');
});

// Privacy page (placeholder)
app.get('/privacy', (req, res) => {
  res.send('<h1>Kebijakan Privasi</h1><p>Halaman Kebijakan Privasi</p>');
});

// Google auth placeholder
app.get('/auth/google', (req, res) => {
  res.send('Google OAuth belum diimplementasikan');
});

// GitHub auth placeholder
app.get('/auth/github', (req, res) => {
  res.send('GitHub OAuth belum diimplementasikan');
});

// ============= FORGOT PASSWORD ROUTES =============

// Forgot password page
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null, success: null });
});

// Handle forgot password request
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.render('forgot-password', { 
      error: 'Email harus diisi!', 
      success: null 
    });
  }

  // Check if email exists
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      console.error(err);
      return res.render('forgot-password', { 
        error: 'Terjadi kesalahan!', 
        success: null 
      });
    }

    if (!user) {
      // Security: Don't reveal if email exists or not
      return res.render('forgot-password', { 
        error: null,
        success: 'Jika email terdaftar, link reset password telah dikirim ke email Anda. Silakan periksa inbox Anda.'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

    // Save token to database
    db.run(
      'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
      [email, resetToken, expiresAt.toISOString()],
      (err) => {
        if (err) {
          console.error(err);
          return res.render('forgot-password', { 
            error: 'Terjadi kesalahan!', 
            success: null 
          });
        }

        // In production, send email here
        // For now, we'll just log the reset link
        const resetLink = `http://localhost:${PORT}/reset-password/${resetToken}`;
        console.log('\n=================================');
        console.log('PASSWORD RESET LINK:');
        console.log(resetLink);
        console.log('=================================\n');

        res.render('forgot-password', { 
          error: null,
          success: 'Link reset password telah dikirim ke email Anda. Periksa console untuk melihat link (demo mode).'
        });
      }
    );
  });
});

// Reset password page
app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;

  // Check if token is valid and not expired
  db.get(
    'SELECT * FROM password_resets WHERE token = ? AND used = 0 AND datetime(expires_at) > datetime("now")',
    [token],
    (err, resetToken) => {
      if (err || !resetToken) {
        return res.render('reset-password', { 
          error: 'Link reset password tidak valid atau sudah kadaluarsa!',
          success: null,
          token: null
        });
      }

      res.render('reset-password', { 
        error: null,
        success: null,
        token: token
      });
    }
  );
});

// Handle reset password
app.post('/reset-password', async (req, res) => {
  const { token, password, confirmPassword } = req.body;

  if (!token || !password || !confirmPassword) {
    return res.render('reset-password', { 
      error: 'Semua field harus diisi!',
      success: null,
      token: token
    });
  }

  if (password !== confirmPassword) {
    return res.render('reset-password', { 
      error: 'Password dan konfirmasi password tidak cocok!',
      success: null,
      token: token
    });
  }

  // Validate password
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.render('reset-password', { 
      error: passwordValidation.message,
      success: null,
      token: token
    });
  }

  // Check if token is valid
  db.get(
    'SELECT * FROM password_resets WHERE token = ? AND used = 0 AND datetime(expires_at) > datetime("now")',
    [token],
    async (err, resetToken) => {
      if (err || !resetToken) {
        return res.render('reset-password', { 
          error: 'Link reset password tidak valid atau sudah kadaluarsa!',
          success: null,
          token: null
        });
      }

      try {
        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user password
        db.run(
          'UPDATE users SET password = ? WHERE email = ?',
          [hashedPassword, resetToken.email],
          (err) => {
            if (err) {
              console.error(err);
              return res.render('reset-password', { 
                error: 'Terjadi kesalahan saat mereset password!',
                success: null,
                token: token
              });
            }

            // Mark token as used
            db.run('UPDATE password_resets SET used = 1 WHERE token = ?', [token], (err) => {
              if (err) console.error(err);
            });

            // Redirect to login with success message
            res.redirect('/login?success=Password berhasil direset! Silakan login dengan password baru.');
          }
        );
      } catch (error) {
        console.error(error);
        res.render('reset-password', { 
          error: 'Terjadi kesalahan server!',
          success: null,
          token: token
        });
      }
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});