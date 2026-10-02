const express = require('express');
const Database = require('better-sqlite3');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const SECRET = process.env.JWT_SECRET || 'doi-chuoi-nay-truoc-khi-chay-that';
const PORT = process.env.PORT || 3000;
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(__dirname, 'mindset.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'staff');
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, price INTEGER NOT NULL, type TEXT NOT NULL, image TEXT);
CREATE TABLE IF NOT EXISTS toppings(id INTEGER PRIMARY KEY, name TEXT NOT NULL, price INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS shifts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, time_in TEXT NOT NULL, time_out TEXT);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT, shift_id INTEGER, user_id INTEGER, created_at TEXT NOT NULL, total INTEGER NOT NULL, method TEXT NOT NULL, items TEXT NOT NULL);
`);

// Giờ Việt Nam, dạng "2026-10-02 14:05:09"
const now = () => new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Ho_Chi_Minh' });

// Dữ liệu mẫu lần chạy đầu
if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) {
  const iu = db.prepare('INSERT INTO users(username,name,password_hash,role) VALUES(?,?,?,?)');
  iu.run('admin', 'Chủ quán', bcrypt.hashSync('admin123', 10), 'admin');
  iu.run('nhanvien', 'Nhân viên mẫu', bcrypt.hashSync('123456', 10), 'staff');
  const ip = db.prepare('INSERT INTO products(name,price,type) VALUES(?,?,?)');
  [['Cà phê đen', 25000, 'Nước'], ['Cà phê sữa', 28000, 'Nước'], ['Latte', 35000, 'Nước'], ['Trà đào', 35000, 'Nước'], ['Bánh tiramisu', 40000, 'Bánh ngọt']].forEach(p => ip.run(...p));
  const it = db.prepare('INSERT INTO toppings(name,price) VALUES(?,?)');
  [['Trân châu đen', 5000], ['Thạch trân châu trắng', 6000], ['Pudding trứng', 8000]].forEach(t => it.run(...t));
}

const app = express();
app.use(express.json());
app.use('/uploads', express.static(UPLOADS));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + (['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) ? ext : '.jpg'));
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(file.mimetype.startsWith('image/') ? null : new Error('Chỉ nhận file ảnh'), file.mimetype.startsWith('image/'))
});

const MGR = ['admin', 'manager'];
const auth = roles => (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').slice(7), SECRET);
    const u = db.prepare('SELECT id,username,name,role FROM users WHERE id=?').get(p.id);
    if (!u) throw new Error();
    if (roles && !roles.includes(u.role)) return res.status(403).json({ error: 'Không đủ quyền' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Phiên đăng nhập hết hạn' }); }
};
const delImg = f => { if (f && f.startsWith('/uploads/')) fs.unlink(path.join(UPLOADS, path.basename(f)), () => {}); };

// ---------- Đăng nhập / ca làm ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || ''));
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash)) return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  if (u.role === 'staff' && !db.prepare('SELECT id FROM shifts WHERE user_id=? AND time_out IS NULL').get(u.id))
    db.prepare('INSERT INTO shifts(user_id,time_in) VALUES(?,?)').run(u.id, now()); // check-in
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '12h' }), user: { id: u.id, username: u.username, name: u.name, role: u.role } });
});

app.post('/api/logout', auth(), (req, res) => { // check-out
  db.prepare('UPDATE shifts SET time_out=? WHERE user_id=? AND time_out IS NULL').run(now(), req.user.id);
  res.json({ ok: true });
});

// ---------- Tài khoản ----------
app.get('/api/users', auth(MGR), (req, res) => res.json(db.prepare('SELECT id,username,name,role FROM users ORDER BY id').all()));

app.post('/api/users', auth(MGR), (req, res) => {
  const { username, name, password, role } = req.body || {};
  if (!username || !name || !password) return res.status(400).json({ error: 'Thiếu thông tin' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' });
  const r = req.user.role === 'admin' && role === 'manager' ? 'manager' : 'staff';
  db.prepare('INSERT INTO users(username,name,password_hash,role) VALUES(?,?,?,?)').run(username.trim(), name.trim(), bcrypt.hashSync(password, 10), r);
  res.json({ ok: true });
});

app.put('/api/users/:id', auth(MGR), (req, res) => {
  const t = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Không tìm thấy' });
  if (t.role === 'admin' && t.id !== req.user.id) return res.status(403).json({ error: 'Không thể sửa admin' });
  if (req.user.role === 'manager' && t.role !== 'staff') return res.status(403).json({ error: 'Quản lý chỉ sửa được nhân viên' });
  const { name, password, role } = req.body || {};
  let newRole = t.role;
  if (req.user.role === 'admin' && t.role !== 'admin' && ['staff', 'manager'].includes(role)) newRole = role; // cấp / xóa quyền quản lý
  db.prepare('UPDATE users SET name=?, role=?, password_hash=? WHERE id=?')
    .run(name || t.name, newRole, password ? bcrypt.hashSync(password, 10) : t.password_hash, t.id);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth(MGR), (req, res) => {
  const t = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Không tìm thấy' });
  if (t.id === req.user.id || t.role === 'admin') return res.status(403).json({ error: 'Không thể xóa tài khoản này' });
  if (req.user.role === 'manager' && t.role !== 'staff') return res.status(403).json({ error: 'Quản lý chỉ xóa được nhân viên' });
  db.prepare('DELETE FROM users WHERE id=?').run(t.id);
  res.json({ ok: true });
});

// ---------- Menu ----------
app.get('/api/menu', auth(), (req, res) => res.json({
  products: db.prepare('SELECT * FROM products ORDER BY id').all(),
  toppings: db.prepare('SELECT * FROM toppings ORDER BY id').all(),
  qr: (db.prepare("SELECT value FROM settings WHERE key='qr'").get() || {}).value || null
}));

app.post('/api/products', auth(MGR), upload.single('image'), (req, res) => {
  const { name, price, type } = req.body;
  if (!name || !(+price >= 0) || !['Nước', 'Bánh ngọt'].includes(type)) return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
  db.prepare('INSERT INTO products(name,price,type,image) VALUES(?,?,?,?)').run(name.trim(), Math.round(+price), type, req.file ? '/uploads/' + req.file.filename : null);
  res.json({ ok: true });
});

app.put('/api/products/:id', auth(MGR), upload.single('image'), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Không tìm thấy' });
  let img = p.image;
  if (req.file) { delImg(p.image); img = '/uploads/' + req.file.filename; }
  db.prepare('UPDATE products SET name=?, price=?, image=? WHERE id=?').run(req.body.name || p.name, req.body.price !== undefined ? Math.round(+req.body.price) : p.price, img, p.id);
  res.json({ ok: true });
});

app.delete('/api/products/:id', auth(MGR), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id);
  if (p) { delImg(p.image); db.prepare('DELETE FROM products WHERE id=?').run(p.id); }
  res.json({ ok: true });
});

app.post('/api/toppings', auth(MGR), (req, res) => {
  const { name, price } = req.body || {};
  if (!name || !(+price >= 0)) return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
  db.prepare('INSERT INTO toppings(name,price) VALUES(?,?)').run(name.trim(), Math.round(+price));
  res.json({ ok: true });
});
app.put('/api/toppings/:id', auth(MGR), (req, res) => {
  const { name, price } = req.body || {};
  db.prepare('UPDATE toppings SET name=?, price=? WHERE id=?').run(name, Math.round(+price), req.params.id);
  res.json({ ok: true });
});
app.delete('/api/toppings/:id', auth(MGR), (req, res) => { db.prepare('DELETE FROM toppings WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// ---------- QR chuyển khoản ----------
app.post('/api/qr', auth(MGR), upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Chưa chọn ảnh' });
  const old = db.prepare("SELECT value FROM settings WHERE key='qr'").get();
  if (old) delImg(old.value);
  db.prepare("INSERT INTO settings(key,value) VALUES('qr',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run('/uploads/' + req.file.filename);
  res.json({ ok: true, qr: '/uploads/' + req.file.filename });
});

// ---------- Đơn hàng (giá tính ở server, không tin client) ----------
app.post('/api/orders', auth(), (req, res) => {
  const { items, method } = req.body || {};
  if (!Array.isArray(items) || !items.length || !['cash', 'transfer'].includes(method)) return res.status(400).json({ error: 'Đơn không hợp lệ' });
  const lines = []; let total = 0;
  for (const it of items) {
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(it.productId);
    const qty = Math.floor(+it.qty);
    if (!p || !(qty > 0)) return res.status(400).json({ error: 'Món không tồn tại' });
    const tops = (it.toppingIds || []).map(id => db.prepare('SELECT * FROM toppings WHERE id=?').get(id)).filter(Boolean);
    const detail = [];
    if (p.type === 'Nước') detail.push('Đường ' + String(it.sugar || '100%').slice(0, 5), 'Đá ' + String(it.ice || '100%').slice(0, 5));
    if (tops.length) detail.push(tops.map(t => t.name).join(', '));
    const price = p.price + tops.reduce((s, t) => s + t.price, 0);
    lines.push({ name: p.name + (detail.length ? ` (${detail.join(' - ')})` : ''), qty, price });
    total += price * qty;
  }
  const shift = db.prepare('SELECT id FROM shifts WHERE user_id=? AND time_out IS NULL').get(req.user.id);
  const r = db.prepare('INSERT INTO orders(shift_id,user_id,created_at,total,method,items) VALUES(?,?,?,?,?,?)')
    .run(shift ? shift.id : null, req.user.id, now(), total, method, JSON.stringify(lines));
  const code = 'MS' + String(r.lastInsertRowid).padStart(5, '0');
  db.prepare('UPDATE orders SET code=? WHERE id=?').run(code, r.lastInsertRowid);
  res.json({ ok: true, code, total });
});

const parseOrders = rows => rows.map(o => ({ ...o, items: JSON.parse(o.items) }));

// ---------- Doanh thu ----------
app.get('/api/revenue', auth(MGR), (req, res) => {
  const { type, value } = req.query;
  const len = type === 'month' ? 7 : 10;
  const rows = db.prepare(`SELECT o.*, COALESCE(u.name,'(đã xóa)') staff FROM orders o LEFT JOIN users u ON u.id=o.user_id WHERE substr(o.created_at,1,${len})=? ORDER BY o.id DESC`).all(String(value || ''));
  const sum = m => rows.filter(o => !m || o.method === m).reduce((s, o) => s + o.total, 0);
  res.json({ total: sum(), cash: sum('cash'), transfer: sum('transfer'), count: rows.length, orders: parseOrders(rows) });
});

// ---------- Ca làm ----------
app.get('/api/shifts', auth(MGR), (req, res) => res.json(db.prepare(`
  SELECT s.*, COALESCE(u.name,'(đã xóa)') name,
  (SELECT COALESCE(SUM(total),0) FROM orders WHERE shift_id=s.id AND method='cash') cash,
  (SELECT COALESCE(SUM(total),0) FROM orders WHERE shift_id=s.id AND method='transfer') transfer
  FROM shifts s LEFT JOIN users u ON u.id=s.user_id WHERE s.user_id=? ORDER BY s.id DESC LIMIT 100`).all(req.query.user_id)));

app.get('/api/shifts/:id/orders', auth(MGR), (req, res) => res.json(parseOrders(db.prepare('SELECT * FROM orders WHERE shift_id=? ORDER BY id').all(req.params.id))));

app.post('/api/shifts/:id/close', auth(MGR), (req, res) => { // chốt ca hộ nhân viên quên đăng xuất
  db.prepare('UPDATE shifts SET time_out=? WHERE id=? AND time_out IS NULL').run(now(), req.params.id);
  res.json({ ok: true });
});

app.use((err, req, res, next) => res.status(400).json({ error: err.message || 'Lỗi' }));
app.listen(PORT, () => console.log(`Mindset POS chạy tại http://localhost:${PORT}`));
