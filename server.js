const express = require('express');
const mysql = require('mysql2');
const app = express();
const port = 3000;
const { exec } = require('child_process'); // Giữ lại cho các tác vụ local nếu cần
const fs = require('fs');
const path = require('path');
const { Client } = require('ssh2');

const routerConfig = {
    host: '192.168.2.1',
    port: 22,
    username: 'root',
    password: '244466666'
};

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'zznoelzz',
    password: '$n0wDrive',
    database: 'user_db'
});

app.use((req, res, next) => {
    if (req.path === '/mainPage.html') {
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
        ip = ip.replace('::ffff:', '');
        if (!ip.startsWith('10.10.')) {
            return res.status(403).send(`
                <html><body style="font-family:sans-serif;text-align:center;padding:60px">
                <h2>🚫 Truy cập bị từ chối</h2>
                <div>Bạn cần kết nối VPN trước khi vào trang này.<br>
                <a href="dashboard.html">Quay lại Dashboard</a></div>
                </body></html>
            `);
        }
    }
    next();
});

app.use(express.static('.'));
app.use(express.json());
app.use('/keys', express.static(path.join(__dirname, 'keys')));

if (!fs.existsSync('./keys')) {
    fs.mkdirSync('./keys');
}

function executeRouterCommand(cmd) {
    return new Promise((resolve, reject) => {
        const conn = new Client();
        conn.on('ready', () => {
            conn.exec(cmd, (err, stream) => {
                if (err) return reject(err);
                let output = '';
                stream.on('data', (data) => { output += data; });
                stream.on('close', () => {
                    conn.end();
                    resolve(output.trim());
                });
            });
        }).on('error', (err) => {
            reject(err);
        }).connect(routerConfig);
    });
}

function getRoleByIP(ip) {
    ip = ip.replace('::ffff:', '');
    if (ip.startsWith('10.10.10.')) return 'boss';
    if (ip.startsWith('10.10.20.')) return 'leader';
    if (ip.startsWith('10.10.30.')) return 'employee';
    return 'unknown';
}

app.get('/api/my-role', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const role = getRoleByIP(clientIP);
    res.json({ role });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    connection.query(
        'SELECT name, role FROM users WHERE username = ? AND password = ?',
        [username, password],
        (err, results) => {
            if (err) return res.status(500).send('Database error.');
            if (results.length)
                res.json({ name: results[0].name, role: results[0].role });
            else
                res.status(401).send('Invalid username or password');
        }
    );
});

app.get('/api/users', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const role = getRoleByIP(clientIP);

    if (role === 'employee' || role === 'unknown') {
        return res.status(403).json({ error: 'Bạn không có quyền xem danh sách nhân sự' });
    }

    connection.query(
        'SELECT id, name, username, password, role, salary, extra FROM users',
        (err, results) => {
            if (err) return res.status(500).send('Database error.');
            if (role === 'leader') {
                results = results.map(u => ({
                    ...u,
                    username: '********',
                    password: '********',
                }));
            }
            res.json(results);
        }
    );
});

app.post('/api/add-employee', async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const role = getRoleByIP(clientIP);

    if (role !== 'boss' && role !== 'leader') {
        return res.status(403).json({ error: 'Quyền truy cập bị từ chối' });
    }

    const { name, username, password, salary, extra } = req.body;

    try {
        executeRouterCommand('cd /etc/wireguard');
        // 1. Sinh Private Key trên Router
        const privateKey = await executeRouterCommand('wg genkey');

        // 2. Từ Private Key đó sinh Public Key trên Router
        const publicKey = await executeRouterCommand(`echo "${privateKey}" | wg pubkey`);

        // 3. Lưu TẤT CẢ vào MySQL (Bao gồm cả Private Key để báo cáo)
        const sql = `INSERT INTO users (name, username, password, role, salary, extra, wg_private_key, wg_public_key) 
                     VALUES (?, ?, ?, 'employee', ?, ?, ?, ?)`;

        connection.query(sql, [name, username, password, salary, extra, privateKey, publicKey], async (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Lỗi Database' });
            }

            const clientIp = `10.10.30.${result.insertId + 10}/32`;

            // 4. Đẩy cấu hình lên Router để VPN hoạt động
            await executeRouterCommand(`wg set wg0 peer ${publicKey} allowed-ips ${clientIp}`);

            // 5. Tạo file .conf cho nhân viên tải
            const configContent = `[Interface]
PrivateKey = ${privateKey}
Address = ${clientIpWithMask}
DNS = 8.8.8.8

[Peer]
PublicKey = /o/HvwqOSQBuMie8gZZazd0Q5k6x7jfxxxAFfUHZi0Q=
Endpoint = 192.168.2.1:51820
AllowedIPs = 0.0.0.0/0`;

            const fileName = `wg_${username}.conf`;
            const filePath = path.join(__dirname, 'keys', fileName);
            fs.writeFileSync(filePath, configContent);

            res.json({
                message: 'Thành công! Toàn bộ Key đã được lưu trữ trong Database.',
                downloadLink: `/keys/${fileName}`
            });
        });

    } catch (error) {
        console.error('SSH/WireGuard Error:', error);
        res.status(500).json({ error: 'Lỗi khi làm việc với Router' });
    }
});

app.listen(port, () => {
    console.log(`✅ Server is running on http://localhost:${port}`);
});