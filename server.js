require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const DB = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const root = __dirname;
const port = process.env.PORT || 3000;
const data = path.join(root, 'data');
const uploads = path.join(root, 'uploads');

fs.mkdirSync(data, { recursive: true });
fs.mkdirSync(uploads, { recursive: true });

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD) {
    console.error('SESSION_SECRET and ADMIN_PASSWORD are required');
    process.exit(1);
}

app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const db = new DB(path.join(data, 'azlia.sqlite'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS works (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    english_title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    type TEXT DEFAULT 'مانهوا',
    status TEXT DEFAULT 'مستمر',
    genres TEXT DEFAULT '',
    author TEXT DEFAULT '',
    cover TEXT DEFAULT '',
    featured INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chapters (
    id INTEGER PRIMARY KEY,
    work_id INTEGER NOT NULL REFERENCES works(id) ON DELETE CASCADE,
    number TEXT NOT NULL,
    title TEXT DEFAULT '',
    pages TEXT DEFAULT '[]',
    published INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER,
    work_id INTEGER,
    PRIMARY KEY(user_id, work_id)
);
`);

const admin = process.env.ADMIN_USERNAME || 'ashealen3';
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

const existingAdmin = db.prepare(
    'SELECT id FROM users WHERE username = ?'
).get(admin);

if (existingAdmin) {
    db.prepare(
        "UPDATE users SET password_hash = ?, role = 'admin' WHERE username = ?"
    ).run(adminHash, admin);
} else {
    db.prepare(
        "INSERT INTO users(username, password_hash, role) VALUES(?, ?, 'admin')"
    ).run(admin, adminHash);
}

app.use(session({
    store: new SQLiteStore({
        db: 'sessions.sqlite',
        dir: data
    }),
    name: 'azlia.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use('/uploads', express.static(uploads));
app.use(express.static(path.join(root, 'public')));

const upload = multer({
    storage: multer.diskStorage({
        destination: uploads,
        filename: (_, file, cb) => {
            cb(
                null,
                Date.now() + '-' +
                Math.random().toString(36).slice(2, 8) +
                path.extname(file.originalname).toLowerCase()
            );
        }
    }),
    limits: {
        fileSize: 12 * 1024 * 1024,
        files: 80
    },
    fileFilter: (_, file, cb) => {
        cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype));
    }
});

const me = user => ({
    id: user.id,
    username: user.username,
    role: user.role
});

const auth = (req, res, next) => {
    if (req.session.user) return next();
    return res.status(401).json({ error: 'سجّل الدخول أولًا' });
};

const isAdmin = (req, res, next) => {
    if (req.session.user?.role === 'admin') return next();
    return res.status(403).json({
        error: 'هذه الصلاحية للمسؤول فقط'
    });
};

function createUserSession(req, res, user) {
    req.session.regenerate(error => {
        if (error) {
            return res.status(500).json({
                error: 'تعذر إنشاء الجلسة'
            });
        }

        req.session.user = me(user);

        req.session.save(error => {
            if (error) {
                return res.status(500).json({
                    error: 'تعذر حفظ جلسة الدخول'
                });
            }

            return res.json({
                user: req.session.user
            });
        });
    });
}

app.get('/api/me', (req, res) => {
    res.json({
        user: req.session.user || null
    });
});

app.post('/api/register', (req, res) => {
    const { username, password } = req.body || {};

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username || '')) {
        return res.status(400).json({
            error: 'اسم المستخدم يجب أن يكون من 3 إلى 24 حرفًا'
        });
    }

    if (typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({
            error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'
        });
    }

    try {
        const result = db.prepare(
            'INSERT INTO users(username, password_hash) VALUES(?, ?)'
        ).run(username, bcrypt.hashSync(password, 12));

        const user = {
            id: Number(result.lastInsertRowid),
            username,
            role: 'user'
        };

        createUserSession(req, res, user);

    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({
                error: 'اسم المستخدم مستخدم بالفعل'
            });
        }

        console.error(error);

        return res.status(500).json({
            error: 'حدث خطأ أثناء إنشاء الحساب'
        });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' ||
        typeof password !== 'string') {
        return res.status(400).json({
            error: 'أدخل اسم المستخدم وكلمة المرور'
        });
    }

    try {
        const user = db.prepare(
            'SELECT * FROM users WHERE username = ?'
        ).get(username);

        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({
                error: 'بيانات الدخول غير صحيحة'
            });
        }

        createUserSession(req, res, user);

    } catch (error) {
        console.error(error);

        return res.status(500).json({
            error: 'حدث خطأ أثناء تسجيل الدخول'
        });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(error => {
        if (error) {
            return res.status(500).json({
                error: 'تعذر تسجيل الخروج'
            });
        }

        res.clearCookie('azlia.sid');
        return res.json({ ok: true });
    });
});

app.get('/api/works', (req, res) => {
    const works = db.prepare(`
        SELECT w.*,
        (
            SELECT COUNT(*)
            FROM chapters c
            WHERE c.work_id = w.id AND c.published = 1
        ) AS chapter_count
        FROM works w
        ORDER BY featured DESC, created_at DESC
    `).all();

    res.json(works.map(work => ({
        ...work,
        genres: work.genres.split(',').filter(Boolean)
    })));
});

app.get('/api/works/:id', (req, res) => {
    const work = db.prepare(
        'SELECT * FROM works WHERE id = ?'
    ).get(req.params.id);

    if (!work) {
        return res.status(404).json({
            error: 'العمل غير موجود'
        });
    }

    db.prepare(
        'UPDATE works SET views = views + 1 WHERE id = ?'
    ).run(work.id);

    const chapters = db.prepare(`
        SELECT id, number, title
        FROM chapters
        WHERE work_id = ? AND published = 1
        ORDER BY CAST(number AS REAL) DESC
    `).all(work.id);

    res.json({
        ...work,
        genres: work.genres.split(',').filter(Boolean),
        chapters
    });
});

app.get('/api/chapters/:id', (req, res) => {
    const chapter = db.prepare(`
        SELECT c.*, w.title AS work_title
        FROM chapters c
        JOIN works w ON w.id = c.work_id
        WHERE c.id = ? AND c.published = 1
    `).get(req.params.id);

    if (!chapter) {
        return res.status(404).json({
            error: 'الفصل غير موجود'
        });
    }

    res.json({
        ...chapter,
        pages: JSON.parse(chapter.pages)
    });
});

app.post('/api/favorites/:id', auth, (req, res) => {
    const has = db.prepare(`
        SELECT 1 FROM favorites
        WHERE user_id = ? AND work_id = ?
    `).get(req.session.user.id, req.params.id);

    if (has) {
        db.prepare(`
            DELETE FROM favorites
            WHERE user_id = ? AND work_id = ?
        `).run(req.session.user.id, req.params.id);
    } else {
        db.prepare(`
            INSERT OR IGNORE INTO favorites(user_id, work_id)
            VALUES(?, ?)
        `).run(req.session.user.id, req.params.id);
    }

    res.json({ favorite: !has });
});

app.get('/api/favorites', auth, (req, res) => {
    const favorites = db.prepare(`
        SELECT w.*
        FROM works w
        JOIN favorites f ON f.work_id = w.id
        WHERE f.user_id = ?
    `).all(req.session.user.id);

    res.json(favorites);
});

app.get('/api/admin/stats', auth, isAdmin, (req, res) => {
    res.json({
        users: db.prepare('SELECT COUNT(*) n FROM users').get().n,
        works: db.prepare('SELECT COUNT(*) n FROM works').get().n,
        chapters: db.prepare('SELECT COUNT(*) n FROM chapters').get().n,
        views: db.prepare(
            'SELECT COALESCE(SUM(views), 0) n FROM works'
        ).get().n
    });
});

app.post('/api/admin/works', auth, isAdmin, upload.single('cover'), (req, res) => {
    const body = req.body;

    if (!body.title?.trim()) {
        return res.status(400).json({
            error: 'اسم العمل مطلوب'
        });
    }

    const result = db.prepare(`
        INSERT INTO works(
            title, english_title, description,
            type, status, genres, author, cover, featured
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        body.title,
        body.english_title || '',
        body.description || '',
        body.type || 'مانهوا',
        body.status || 'مستمر',
        body.genres || '',
        body.author || '',
        req.file ? '/uploads/' + req.file.filename : '',
        body.featured === '1' ? 1 : 0
    );

    res.json({ id: result.lastInsertRowid });
});

app.delete('/api/admin/works/:id', auth, isAdmin, (req, res) => {
    db.prepare(
        'DELETE FROM works WHERE id = ?'
    ).run(req.params.id);

    res.json({ ok: true });
});

app.post('/api/admin/works/:id/chapters', auth, isAdmin, upload.array('pages', 80), (req, res) => {
    const work = db.prepare(
        'SELECT id FROM works WHERE id = ?'
    ).get(req.params.id);

    if (!work) {
        return res.status(404).json({
            error: 'العمل غير موجود'
        });
    }

    const pages = (req.files || []).map(
        file => '/uploads/' + file.filename
    );

    const result = db.prepare(`
        INSERT INTO chapters(work_id, number, title, pages, published)
        VALUES(?, ?, ?, ?, 1)
    `).run(
        req.params.id,
        req.body.number || '1',
        req.body.title || '',
        JSON.stringify(pages)
    );

    res.json({ id: result.lastInsertRowid });
});

app.delete('/api/admin/chapters/:id', auth, isAdmin, (req, res) => {
    db.prepare(
        'DELETE FROM chapters WHERE id = ?'
    ).run(req.params.id);

    res.json({ ok: true });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(root, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log('Manga Azlia running on port ' + port);
});
