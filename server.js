const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'rahasia_negara_api_sangat_aman'; // Kunci untuk JWT

// Menggunakan body-parser untuk membaca JSON dari body request
app.use(bodyParser.json());

// --- DATABASE SEMENTARA (ARRAY) ---
// Kita gunakan array sebagai pengganti database agar mudah dijalankan tanpa setup DB
const users = []; 
const activities = []; 

// ==========================================
// A. IMPLEMENTASI MIDDLEWARE [cite: 29]
// ==========================================

// 1. Request Logger Middleware [cite: 33]
// Mencatat setiap request (method dan URL) ke console
const requestLogger = (req, res, next) => {
    console.log(`[LOG] ${new Date().toISOString()} | ${req.method} ${req.originalUrl}`);
    next();
};

// Pasang logger secara global agar berjalan di semua request
app.use(requestLogger);

// 2. Auth Middleware (Cek JWT) [cite: 30]
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Format header biasanya: "Bearer <token>"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Akses ditolak: Token tidak ditemukan' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Akses ditolak: Token tidak valid' });
        }
        req.user = user; // Simpan data user (dari token) ke request object
        next();
    });
};

// 3. Role Middleware (Cek Hak Akses) [cite: 31]
// Fungsi ini menerima role yang diizinkan (misal: 'admin')
const authorizeRole = (requiredRole) => {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).json({ 
                message: `Akses terlarang: Hanya ${requiredRole} yang boleh mengakses ini.` 
            });
        }
        next();
    };
};

// 4. Activity Validation Middleware [cite: 32]
// Validasi input saat Admin membuat kegiatan
const validateActivity = (req, res, next) => {
    const { title, description, date } = req.body;
    if (!title || !description || !date) {
        return res.status(400).json({ 
            message: 'Data tidak lengkap. Title, description, dan date harus diisi.' 
        });
    }
    next();
};

// ==========================================
// B. ENDPOINTS & LOGIKA AUTENTIKASI [cite: 34]
// ==========================================

// 1. POST /register [cite: 36]
app.post('/register', (req, res) => {
    const { username, password, role } = req.body;
    
    // Validasi sederhana
    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, dan role harus diisi' });
    }

    // Cek apakah user sudah ada
    const userExists = users.find(u => u.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'Username sudah digunakan' });
    }

    // Simpan user baru (Password sebaiknya di-hash di produksi, disini plaintext untuk demo)
    const newUser = { id: users.length + 1, username, password, role };
    users.push(newUser);

    res.status(201).json({ message: 'Registrasi berhasil', data: newUser });
});

// 2. POST /login [cite: 38]
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Cari user
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Username atau password salah' });
    }

    // Buat Token JWT
    // Payload berisi id, username, dan role
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login berhasil', token });
});

// 3. GET /activities [cite: 39]
// Bisa diakses semua user yang login (Admin & Mahasiswa)
app.get('/activities', authenticateToken, (req, res) => {
    res.json(activities);
});

// 4. POST /activities (Admin Only) [cite: 41]
app.post('/activities', authenticateToken, authorizeRole('admin'), validateActivity, (req, res) => {
    const { title, description, date } = req.body;
    
    const newActivity = {
        id: activities.length + 1,
        title,
        description,
        date,
        participants: [] // List mahasiswa yang join
    };
    
    activities.push(newActivity);
    res.status(201).json({ message: 'Kegiatan berhasil dibuat', data: newActivity });
});

// 5. PUT /activities/:id (Admin Only) [cite: 43]
app.put('/activities/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
    const activityId = parseInt(req.params.id);
    const activityIndex = activities.findIndex(a => a.id === activityId);

    if (activityIndex === -1) {
        return res.status(404).json({ message: 'Kegiatan tidak ditemukan' });
    }

    // Update data kegiatan
    const { title, description, date } = req.body;
    if (title) activities[activityIndex].title = title;
    if (description) activities[activityIndex].description = description;
    if (date) activities[activityIndex].date = date;

    res.json({ message: 'Kegiatan berhasil diperbarui', data: activities[activityIndex] });
});

// 6. POST /activities/:id/join (Mahasiswa Only) [cite: 44]
app.post('/activities/:id/join', authenticateToken, authorizeRole('mahasiswa'), (req, res) => {
    const activityId = parseInt(req.params.id);
    const activity = activities.find(a => a.id === activityId);

    if (!activity) {
        return res.status(404).json({ message: 'Kegiatan tidak ditemukan' });
    }

    // Cek apakah mahasiswa sudah join
    const alreadyJoined = activity.participants.includes(req.user.username);
    if (alreadyJoined) {
        return res.status(400).json({ message: 'Anda sudah terdaftar di kegiatan ini' });
    }

    // Tambahkan username mahasiswa ke daftar peserta
    activity.participants.push(req.user.username);
    res.json({ message: `Berhasil mendaftar ke kegiatan: ${activity.title}` });
});

// Jalankan Server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});