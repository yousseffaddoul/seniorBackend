const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');




const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
const PORT = 3000;
const SECRET = process.JWT_SECRET || '2482000';

// =====================================
// MIDDLEWARE
// =====================================
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));

app.use('/uploads', express.static('uploads'));

// =====================================
// DATABASE
// =====================================
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'agrilebanon'
});

db.connect(err => {
  if (err) {
    console.error('❌ MySQL Error:', err);
    process.exit(1);
  }
  console.log('✅ MySQL Connected');
});

// =====================================
// JWT HELPERS
// =====================================
function generateToken(user) {
  return jwt.sign(
    {
      user_id: user.user_id,
      email: user.email,
      role: user.role
    },
    SECRET,
    { expiresIn: '1h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ error: 'Token missing' });

  const token = authHeader.split(' ')[1];

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ error: 'Invalid or expired token' });

    req.user = decoded;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res.status(403).json({ error: 'Access denied' });
    next();
  };
}

// =====================================
// FILE UPLOAD
// =====================================
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage });

// =====================================
// REGISTER USER
// =====================================
app.post('/register', (req, res) => {
  const { name, email, password, role, preferred_language } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email & password required' });

  const user_id = uuidv4();
  const hashedPassword = bcrypt.hashSync(password, 10);

  const sql = `
    INSERT INTO users (user_id, name, email, password, role, preferred_language)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [user_id, name, email, hashedPassword, role || 'user', preferred_language || 'en'],
    err => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY')
          return res.status(400).json({ error: 'Email already exists' });
        return res.status(500).json(err);
      }

      const token = generateToken({ user_id, email, role });

      res.json({ message: 'User registered', token, role });
    }
  );
});

// =====================================
// REGISTER FARMER
// =====================================
app.post('/api/farmers/register', upload.single('farmPhoto'), (req, res) => {
  const {
    name,
    email,
    password,
    farmName,
    location,
    farmSize,
    plantingStartDate,
    irrigationType,
    preferredLanguage
  } = req.body;

  if (!email || !password || !farmName)
    return res.status(400).json({ error: 'Missing required fields' });

  const user_id = uuidv4();
  const farmer_id = uuidv4();
  const hashedPassword = bcrypt.hashSync(password, 10);
  const farmPhoto = req.file ? req.file.filename : null;

  const userSql = `
    INSERT INTO users (user_id, name, email, password, role, preferred_language)
    VALUES (?, ?, ?, ?, 'farmer', ?)
  `;

  const farmerSql = `
    INSERT INTO farmers
    (farmer_id, farm_name, location, farm_size,
     planting_start_date, irrigation_type, farm_photo, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(userSql, [user_id, name, email, hashedPassword, preferredLanguage], err => {
    if (err) return res.status(500).json(err);

    db.query(
      farmerSql,
      [
        farmer_id,
        farmName,
        location,
        farmSize,
        plantingStartDate,
        irrigationType,
        farmPhoto,
        user_id
      ],
      err2 => {
        if (err2) return res.status(500).json(err2);

        const token = generateToken({
          user_id,
          email,
          role: 'farmer'
        });

        res.json({
          message: 'Farmer registered successfully',
          token,
          role: 'farmer'
        });
      }
    );
  });
});

// =====================================
// LOGIN
// =====================================
app.post('/login', (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role)
    return res.status(400).json({ error: 'Email, password, role required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json(err);
    if (!results.length)
      return res.status(401).json({ error: 'Invalid email' });

    const user = results[0];

    if (user.role !== role)
      return res.status(401).json({ error: 'Incorrect role' });

    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid password' });

    res.json({
      token: generateToken(user),
      role: user.role
    });
  });
});


// =====================================
// FARMER DASHBOARD (JWT PROTECTED)
// =====================================
app.get(
  '/farmer-dashboard',
  authenticateToken,
  authorizeRole('farmer'),
  (req, res) => {
    const userId = req.user.user_id;

    const sql = `
      SELECT 
        u.name,
        u.email,
        u.preferred_language,
        f.farm_name,
        f.location,
        f.farm_size,
        f.planting_start_date,
        f.irrigation_type,
        f.farm_photo
      FROM users u
      JOIN farmers f ON u.user_id = f.user_id
      WHERE u.user_id = ?
    `;

    db.query(sql, [userId], (err, result) => {
      if (err) return res.status(500).json(err);
      if (!result.length)
        return res.status(404).json({ error: 'Farmer not found' });

      res.json(result[0]);
    });
  }
);
app.post('/api/suppliers/register', upload.single('certification'), async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      company,
      company_type,
      product_category,
      description,
      language,
      notifications,
      dark_mode
    } = req.body;

    if (!email || !password || !company) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 🔐 IDs
    const user_id = uuidv4();
    const supplier_id = uuidv4();

    // 🔐 Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // 📁 File
    const certification = req.file ? req.file.filename : null;

    // 🔄 Boolean conversion
    const notif = notifications === 'true' ? 1 : 0;
    const dark = dark_mode === 'true' ? 1 : 0;

    // 1️⃣ INSERT USER
    const userSql = `
      INSERT INTO users (user_id, name, email, password, role, preferred_language)
      VALUES (?, ?, ?, ?, 'supplier', ?)
    `;

    // 2️⃣ INSERT SUPPLIER PROFILE
    const supplierSql = `
      INSERT INTO suppliers
      (
        supplier_id,
        company_name,
        company_type,
        product_category,
        company_description,
        certification_file,
        notifications,
        dark_mode,
        user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      userSql,
      [user_id, name, email, hashedPassword, language || 'en'],
      err => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY')
            return res.status(400).json({ error: 'Email already exists' });
          return res.status(500).json(err);
        }

        db.query(
          supplierSql,
          [
            supplier_id,
            company,
            company_type,
            product_category,
            description,
            certification,
            notif,
            dark,
            user_id
          ],
          err2 => {
            if (err2) return res.status(500).json(err2);

            const token = generateToken({
              user_id,
              email,
              role: 'supplier'
            });

            res.json({
              message: 'Supplier registered successfully',
              token,
              role: 'supplier'
            });
          }
        );
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});
function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admins only' });
  next();
}

app.get(
  '/api/admin/dashboard',
  authenticateToken,
  authorizeAdmin,
  (req, res) => {

    // Stats excluding admins
    const statsSql = `
      SELECT
        (SELECT COUNT(*) FROM users WHERE role != 'admin') AS totalUsers,
        (SELECT COUNT(*) FROM users WHERE role='farmer') AS farmers,
        (SELECT COUNT(*) FROM users WHERE role='supplier') AS suppliers,
        (SELECT COUNT(*) FROM users WHERE role='expert') AS experts
    `;

    // Last 5 activity logs (can include admin actions or not depending on your design)
    const activitySql = `
      SELECT message, created_at
      FROM activity_logs
      ORDER BY created_at DESC
      LIMIT 5
    `;

    db.query(statsSql, (err, stats) => {
      if (err) return res.status(500).json(err);

      db.query(activitySql, (err2, activity) => {
        if (err2) return res.status(500).json(err2);

        res.json({
          stats: stats[0],
          activity
        });
      });
    });
  }
);
// Get all users except admins
app.get('/api/admin/users', authenticateToken, authorizeAdmin, (req, res) => {
  const sql = `SELECT user_id, name, email, role FROM users WHERE role != 'admin'`;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json(err);
    res.json(results);
  });
});


// Add a new user
app.post('/api/admin/users', authenticateToken, authorizeAdmin, (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  const user_id = uuidv4();
  const sql = `INSERT INTO users (user_id, name, email, password, role) VALUES (?, ?, ?, ?, ?)`;
  db.query(sql, [user_id, name, email, hashedPassword, role], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: 'User added successfully' });
  });
});


// Update user
app.put('/api/admin/users/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const { name, email, role } = req.body;
  const sql = `UPDATE users SET name=?, email=?, role=? WHERE user_id=?`;
  db.query(sql, [name, email, role, req.params.id], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: 'User updated successfully' });
  });
});


// Delete user
app.delete('/api/admin/users/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const sql = `DELETE FROM users WHERE user_id=? AND role != 'admin'`;
  db.query(sql, [req.params.id], (err) => {
    if (err) return res.status(500).json(err);
    res.json({ message: 'User deleted successfully' });
  });
});



// =====================================
// START SERVER
// =====================================
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
