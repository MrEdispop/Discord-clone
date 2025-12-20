const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');

const { initializeDatabase, userDB, messageDB, dmDB, fileDB, reactionDB, friendDB, serverDB, db } = require('./database');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const ADMIN_EMAILS = ['admin@discord.com', 'test@test.com']; // Админы

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Create uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { 
        fileSize: 100 * 1024 * 1024 // 100MB для всех
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain', 'audio/mpeg', 'audio/mp3', 'video/mp4', 'video/webm', 'video/quicktime',
            'application/zip', 'application/x-rar-compressed'
        ];
        
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Недопустимый тип файла'), false);
        }
    }
});

// Initialize database
initializeDatabase();

// JWT middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Неверный токен' });
        }
        req.user = user;
        next();
    });
}

// Check if user is admin
function isAdmin(email) {
    return ADMIN_EMAILS.includes(email);
}

// ==================== API ROUTES ====================

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        if (password.length < 3) {
            return res.status(400).json({ error: 'Пароль минимум 3 символа' });
        }
        
        const existingUser = await userDB.findByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email уже зарегистрирован' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await userDB.create(username, email, hashedPassword);
        
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar: username.charAt(0).toUpperCase(),
                has_nitro: false,
                is_admin: isAdmin(email)
            }
        });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Ошибка регистрации' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }
        
        const user = await userDB.findByEmail(email);
        if (!user) {
            return res.status(400).json({ error: 'Неверные учетные данные' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Неверные учетные данные' });
        }
        
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '365d' });
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar: user.avatar || user.username.charAt(0).toUpperCase(),
                banner_url: user.banner_url || null,
                has_nitro: user.has_nitro || false,
                nitro_expires_at: user.nitro_expires_at || null,
                status: user.status || 'Online',
                is_admin: isAdmin(user.email)
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Ошибка входа' });
    }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await userDB.findById(req.user.id);
        user.is_admin = isAdmin(user.email);
        res.json(user);
    } catch (error) {
        console.error('Ошибка получения профиля:', error);
        res.status(500).json({ error: 'Ошибка получения профиля' });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { username, status } = req.body;
        const updates = [];
        const params = [];
        
        if (username && username.trim().length >= 2) {
            updates.push('username = ?');
            params.push(username.trim());
        }
        
        if (status && ['Online', 'Idle', 'Do Not Disturb', 'Invisible'].includes(status)) {
            updates.push('status = ?');
            params.push(status);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }
        
        params.push(req.user.id);
        const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
        
        db.run(sql, params, function(err) {
            if (err) {
                console.error('Ошибка обновления профиля:', err);
                return res.status(500).json({ error: 'Ошибка обновления профиля' });
            }
            
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Ошибка обновления профиля:', error);
        res.status(500).json({ error: 'Ошибка обновления' });
    }
});

// ==================== AVATAR & BANNER ROUTES ====================

// Upload avatar (БЕСПЛАТНО для всех)
app.post('/api/upload-avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }

        // Разрешить все изображения
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
        
        if (!allowedTypes.includes(req.file.mimetype)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                error: 'Разрешены только JPG, PNG, WebP, GIF' 
            });
        }

        // Получить текущего пользователя
        const user = await userDB.findById(req.user.id);
        
        // Удалить старую аватарку если есть
        if (user.avatar && user.avatar.startsWith('uploads/')) {
            const oldPath = path.join(__dirname, user.avatar);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }

        // Сохранить новую аватарку
        const avatarPath = `uploads/${req.file.filename}`;
        await userDB.updateAvatar(req.user.id, avatarPath);
        
        res.json({
            success: true,
            avatarUrl: `/${avatarPath}`,
            message: 'Аватарка успешно обновлена!'
        });
    } catch (error) {
        console.error('Ошибка загрузки аватарки:', error);
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Ошибка загрузки аватарки' });
    }
});

// Upload banner (БЕСПЛАТНО для всех)
app.post('/api/upload-banner', authenticateToken, upload.single('banner'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }

        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
        
        if (!allowedTypes.includes(req.file.mimetype)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                error: 'Разрешены только JPG, PNG, WebP, GIF' 
            });
        }

        // Получить пользователя
        const user = await userDB.findById(req.user.id);
        
        // Удалить старый баннер если есть
        if (user.banner_url && user.banner_url.startsWith('uploads/')) {
            const oldPath = path.join(__dirname, user.banner_url);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }

        // Сохранить баннер
        const bannerPath = `uploads/${req.file.filename}`;
        await userDB.updateBanner(req.user.id, bannerPath);
        
        res.json({
            success: true,
            bannerUrl: `/${bannerPath}`,
            message: 'Баннер успешно обновлен!'
        });
    } catch (error) {
        console.error('Ошибка загрузки баннера:', error);
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Ошибка загрузки баннера' });
    }
});

// ==================== NITRO ROUTES ====================

// Get Nitro status
app.get('/api/nitro/status', authenticateToken, (req, res) => {
    const sql = 'SELECT has_nitro, nitro_expires_at FROM users WHERE id = ?';
    db.get(sql, [req.user.id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка получения статуса Nitro' });
        }
        
        res.json({
            has_nitro: row?.has_nitro || false,
            nitro_expires_at: row?.nitro_expires_at || null,
            is_active: row?.has_nitro && (!row.nitro_expires_at || new Date(row.nitro_expires_at) > new Date())
        });
    });
});

// Activate Nitro (бесплатно для всех)
app.post('/api/nitro/activate', authenticateToken, (req, res) => {
    // Бесплатный Nitro на 100 лет
    const expiresAt = new Date();
    expiresAt.setFullYear(expiresAt.getFullYear() + 100);
    
    const sql = 'UPDATE users SET has_nitro = 1, nitro_expires_at = ? WHERE id = ?';
    db.run(sql, [expiresAt.toISOString(), req.user.id], function(err) {
        if (err) {
            console.error('Ошибка активации Nitro:', err);
            return res.status(500).json({ error: 'Ошибка активации Nitro' });
        }
        
        res.json({
            success: true,
            has_nitro: true,
            nitro_expires_at: expiresAt.toISOString(),
            plan_type: 'free',
            message: '🎉 Discord Nitro успешно активирован БЕСПЛАТНО!'
        });
    });
});

// Выдать Nitro другому пользователю (только админы)
app.post('/api/admin/give-nitro', authenticateToken, (req, res) => {
    const { userId } = req.body;
    
    // Проверить что пользователь - админ
    const checkAdminSql = 'SELECT email FROM users WHERE id = ?';
    db.get(checkAdminSql, [req.user.id], (err, user) => {
        if (err || !user || !isAdmin(user.email)) {
            return res.status(403).json({ error: 'Только админы могут выдавать Nitro' });
        }
        
        // Выдать Nitro
        const expiresAt = new Date();
        expiresAt.setFullYear(expiresAt.getFullYear() + 100);
        
        const giveNitroSql = 'UPDATE users SET has_nitro = 1, nitro_expires_at = ? WHERE id = ?';
        db.run(giveNitroSql, [expiresAt.toISOString(), userId], function(giveErr) {
            if (giveErr) {
                console.error('Ошибка выдачи Nitro:', giveErr);
                return res.status(500).json({ error: 'Ошибка выдачи Nitro' });
            }
            
            res.json({
                success: true,
                message: `Nitro успешно выдан пользователю ID: ${userId}`
            });
        });
    });
});

// Получить всех пользователей (для админ панели)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    // Проверить админа
    const checkAdminSql = 'SELECT email FROM users WHERE id = ?';
    db.get(checkAdminSql, [req.user.id], async (err, user) => {
        if (err || !user || !isAdmin(user.email)) {
            return res.status(403).json({ error: 'Доступ запрещен' });
        }
        
        try {
            const users = await userDB.getAll();
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Ошибка получения пользователей' });
        }
    });
});

// ==================== SERVER ROUTES ====================

// Create server
app.post('/api/servers', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Название сервера должно быть не менее 2 символов' });
        }
        
        const server = await serverDB.create(name.trim(), req.user.id);
        await serverDB.addMember(server.id, req.user.id);
        
        // Create default channels
        const defaultChannels = [
            { name: 'general', type: 'text' },
            { name: 'voice-chat', type: 'voice' }
        ];
        
        for (const channel of defaultChannels) {
            const sql = 'INSERT INTO channels (name, type, server_id) VALUES (?, ?, ?)';
            db.run(sql, [channel.name, channel.type, server.id]);
        }
        
        res.status(201).json(server);
    } catch (error) {
        console.error('Ошибка создания сервера:', error);
        res.status(500).json({ error: 'Ошибка создания сервера' });
    }
});

// Get user's servers (ИСПРАВЛЕНО!)
app.get('/api/servers', authenticateToken, async (req, res) => {
    try {
        const servers = await serverDB.getUserServers(req.user.id);
        
        // Если нет серверов, создать дефолтный
        if (servers.length === 0) {
            const defaultServer = await serverDB.create(`${req.user.username}'s Server`, req.user.id);
            await serverDB.addMember(defaultServer.id, req.user.id);
            
            // Создать дефолтные каналы
            const defaultChannels = [
                { name: 'general', type: 'text' },
                { name: 'voice-chat', type: 'voice' }
            ];
            
            for (const channel of defaultChannels) {
                const sql = 'INSERT INTO channels (name, type, server_id) VALUES (?, ?, ?)';
                db.run(sql, [channel.name, channel.type, defaultServer.id]);
            }
            
            res.json([defaultServer]);
        } else {
            res.json(servers);
        }
    } catch (error) {
        console.error('Ошибка получения серверов:', error);
        res.status(500).json({ error: 'Ошибка получения серверов' });
    }
});

// Get server members
app.get('/api/servers/:serverId/members', authenticateToken, async (req, res) => {
    try {
        const members = await serverDB.getMembers(req.params.serverId);
        res.json(members);
    } catch (error) {
        console.error('Ошибка получения участников:', error);
        res.status(500).json({ error: 'Ошибка получения участников' });
    }
});

// Join server
app.post('/api/servers/:serverId/join', authenticateToken, async (req, res) => {
    try {
        const serverId = req.params.serverId;
        await serverDB.addMember(serverId, req.user.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка вступления на сервер:', error);
        res.status(500).json({ error: 'Ошибка вступления на сервер' });
    }
});

// ==================== OTHER ROUTES ====================

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await userDB.getAll();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Ошибка получения пользователей' });
    }
});

// Get messages by channel
app.get('/api/messages/:channelId', authenticateToken, async (req, res) => {
    try {
        const messages = await messageDB.getByChannel(req.params.channelId);
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Ошибка получения сообщений' });
    }
});

// Get direct messages
app.get('/api/dm/:userId', authenticateToken, async (req, res) => {
    try {
        const messages = await dmDB.getConversation(req.user.id, req.params.userId);
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Ошибка получения сообщений' });
    }
});

// Friend routes
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const friends = await friendDB.getFriends(req.user.id);
        res.json(friends);
    } catch (error) {
        console.error('Ошибка получения друзей:', error);
        res.status(500).json({ error: 'Ошибка получения друзей' });
    }
});

app.get('/api/friends/pending', authenticateToken, async (req, res) => {
    try {
        const requests = await friendDB.getPendingRequests(req.user.id);
        res.json(requests);
    } catch (error) {
        console.error('Ошибка получения запросов:', error);
        res.status(500).json({ error: 'Ошибка получения запросов' });
    }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.body;
        const result = await friendDB.sendRequest(req.user.id, friendId);

        if (result.changes > 0) {
            const receiverSocket = Array.from(users.values()).find(u => u.id === friendId);
            if (receiverSocket) {
                io.to(receiverSocket.socketId).emit('new-friend-request');
            }
        }

        res.sendStatus(200);
    } catch (error) {
        console.error('Ошибка запроса дружбы:', error);
        res.status(500).json({ error: 'Ошибка запроса дружбы' });
    }
});

app.post('/api/friends/accept', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.body;
        await friendDB.acceptRequest(req.user.id, friendId);
        res.sendStatus(200);
    } catch (error) {
        console.error('Ошибка принятия запроса:', error);
        res.status(500).json({ error: 'Ошибка принятия запроса' });
    }
});

app.post('/api/friends/reject', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.body;
        await friendDB.rejectRequest(req.user.id, friendId);
        res.sendStatus(200);
    } catch (error) {
        console.error('Ошибка отклонения запроса:', error);
        res.status(500).json({ error: 'Ошибка отклонения запроса' });
    }
});

app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
    try {
        await friendDB.removeFriend(req.user.id, req.params.friendId);
        res.sendStatus(200);
    } catch (error) {
        console.error('Ошибка удаления друга:', error);
        res.status(500).json({ error: 'Ошибка удаления друга' });
    }
});

// File upload
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Файл не загружен' });
        }
        
        const { channelId } = req.body;
        const fileRecord = await fileDB.create(
            req.file.filename,
            req.file.path,
            req.file.mimetype,
            req.file.size,
            req.user.id,
            channelId
        );
        
        res.json({
            id: fileRecord.id,
            filename: req.file.originalname,
            url: `/uploads/${req.file.filename}`,
            type: req.file.mimetype,
            size: req.file.size
        });
    } catch (error) {
        console.error('Ошибка загрузки:', error);
        res.status(500).json({ error: 'Ошибка загрузки' });
    }
});

// ==================== SOCKET.IO ====================

// Store connected users
const users = new Map();
const rooms = new Map();

// Socket.IO connection handling
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Ошибка аутентификации'));
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error('Ошибка аутентификации'));
        socket.userId = decoded.id;
        socket.userEmail = decoded.email;
        next();
    });
});

io.on('connection', async (socket) => {
    console.log('Пользователь подключился:', socket.userId);
    
    try {
        const user = await userDB.findById(socket.userId);
        
        users.set(socket.id, {
            ...user,
            socketId: socket.id
        });
        
        // Update user status
        await userDB.updateStatus(socket.userId, 'Online');
        
        io.emit('user-list-update', Array.from(users.values()));
    } catch (error) {
        console.error('Ошибка загрузки пользователя:', error);
    }

    // User sends message
    socket.on('send-message', async (messageData) => {
        try {
            const { channelId, message } = messageData;
            
            // Get user info
            const user = await userDB.findById(socket.userId);
            
            // Save to database
            const savedMessage = await messageDB.create(
                message.text,
                socket.userId,
                channelId
            );
            
            // Broadcast message with full user info
            const broadcastMessage = {
                id: savedMessage.id,
                author: user.username,
                avatar: user.avatar || user.username.charAt(0).toUpperCase(),
                text: message.text,
                timestamp: new Date()
            };
            
            io.emit('new-message', {
                channelId,
                message: broadcastMessage
            });
        } catch (error) {
            console.error('Message error:', error);
        }
    });

    // Direct message
    socket.on('send-dm', async (data) => {
        try {
            const { receiverId, message } = data;
            const sender = await userDB.findById(socket.userId);

            const savedMessage = await dmDB.create(
                message.text,
                socket.userId,
                receiverId
            );

            const messagePayload = {
                id: savedMessage.id,
                author: sender.username,
                avatar: sender.avatar || sender.username.charAt(0).toUpperCase(),
                text: message.text,
                timestamp: new Date()
            };

            // Send to receiver
            const receiverSocket = Array.from(users.values())
                .find(u => u.id === receiverId);
            
            if (receiverSocket) {
                io.to(receiverSocket.socketId).emit('new-dm', {
                    senderId: socket.userId,
                    message: messagePayload
                });
            }
            
            // Send back to sender
            socket.emit('dm-sent', {
                receiverId,
                message: messagePayload
            });
        } catch (error) {
            console.error('DM error:', error);
        }
    });

    // Add reaction
    socket.on('add-reaction', async (data) => {
        try {
            const { messageId, emoji } = data;
            await reactionDB.add(emoji, messageId, socket.userId);
            
            const reactions = await reactionDB.getByMessage(messageId);
            io.emit('reaction-update', { messageId, reactions });
        } catch (error) {
            console.error('Reaction error:', error);
        }
    });

    // Remove reaction
    socket.on('remove-reaction', async (data) => {
        try {
            const { messageId, emoji } = data;
            await reactionDB.remove(emoji, messageId, socket.userId);
            
            const reactions = await reactionDB.getByMessage(messageId);
            io.emit('reaction-update', { messageId, reactions });
        } catch (error) {
            console.error('Reaction error:', error);
        }
    });

    // Voice activity detection
    socket.on('voice-activity', (data) => {
        socket.broadcast.emit('user-speaking', {
            userId: socket.userId,
            speaking: data.speaking
        });
    });

    // Join voice channel
    socket.on('join-voice-channel', (channelData) => {
        const { channelName, userId } = channelData;
        
        socket.join(`voice-${channelName}`);
        
        if (!rooms.has(channelName)) {
            rooms.set(channelName, new Set());
        }
        rooms.get(channelName).add(socket.id);
        
        socket.to(`voice-${channelName}`).emit('user-joined-voice', {
            userId,
            socketId: socket.id
        });
        
        const existingUsers = Array.from(rooms.get(channelName))
            .filter(id => id !== socket.id)
            .map(id => users.get(id));
        
        socket.emit('existing-voice-users', existingUsers);
    });

    // WebRTC signaling
    socket.on('offer', (data) => {
        socket.to(data.to).emit('offer', {
            offer: data.offer,
            from: socket.id
        });
    });

    socket.on('answer', (data) => {
        socket.to(data.to).emit('answer', {
            answer: data.answer,
            from: socket.id
        });
    });

    socket.on('ice-candidate', (data) => {
        socket.to(data.to).emit('ice-candidate', {
            candidate: data.candidate,
            from: socket.id
        });
    });

    socket.on('leave-voice-channel', (channelName) => {
        socket.leave(`voice-${channelName}`);
        
        if (rooms.has(channelName)) {
            rooms.get(channelName).delete(socket.id);
            socket.to(`voice-${channelName}`).emit('user-left-voice', socket.id);
        }
    });

    // Handle call initiation
    socket.on('initiate-call', (data) => {
        const { to, type, from } = data;
        console.log(`Звонок от ${from.id} к ${to}, тип: ${type}`);
        
        const receiverSocket = Array.from(users.values()).find(u => u.id === to);
        if (receiverSocket) {
            io.to(receiverSocket.socketId).emit('incoming-call', {
                from: {
                    id: from.id,
                    username: from.username,
                    socketId: socket.id,
                    avatar: from.username?.charAt(0).toUpperCase()
                },
                type: type
            });
        } else {
            socket.emit('call-rejected', { message: 'Пользователь не в сети' });
        }
    });

    socket.on('accept-call', (data) => {
        const { to, from } = data;
        console.log(`Звонок принят ${from.id}, подключение к ${to}`);
        
        io.to(to).emit('call-accepted', {
            from: {
                id: from.id,
                username: from.username,
                socketId: socket.id
            }
        });
    });

    socket.on('reject-call', (data) => {
        const { to } = data;
        console.log(`Звонок отклонен, уведомление ${to}`);
        
        io.to(to).emit('call-rejected', {
            from: socket.id,
            message: 'Звонок отклонен'
        });
    });
    
    socket.on('video-toggle', (data) => {
        const { to, enabled } = data;
        if (to) {
            io.to(to).emit('video-toggle', {
                from: socket.id,
                enabled: enabled
            });
        }
    });
    
    socket.on('end-call', (data) => {
        const { to } = data;
        if (to) {
            io.to(to).emit('call-ended', { from: socket.id });
        }
    });

    // Handle disconnection
    socket.on('disconnect', async () => {
        const user = users.get(socket.id);
        
        if (user) {
            console.log(`${user.username} отключился`);
            
            try {
                await userDB.updateStatus(socket.userId, 'Offline');
            } catch (error) {
                console.error('Ошибка обновления статуса:', error);
            }
            
            rooms.forEach((members, roomName) => {
                if (members.has(socket.id)) {
                    members.delete(socket.id);
                    io.to(`voice-${roomName}`).emit('user-left-voice', socket.id);
                }
            });
            
            users.delete(socket.id);
            io.emit('user-list-update', Array.from(users.values()));
        }
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`Discord Clone сервер запущен на http://localhost:${PORT}`);
    console.log(`Откройте http://localhost:${PORT}/login.html в браузере`);
    console.log(`👑 Админы: ${ADMIN_EMAILS.join(', ')}`);
});
