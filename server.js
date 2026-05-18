const express = require('express');
const mysql = require('mysql2');
const app = express();
const port = 3000;
const fs = require('fs');
const path = require('path');
const { Client } = require('ssh2');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

app.set('trust proxy', true);

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

app.use(express.static(__dirname));
app.use(express.json());
app.use('/keys', express.static(path.join(__dirname, 'keys')));

if (!fs.existsSync('./keys')) {
    fs.mkdirSync('./keys');
}

app.use((req, res, next) => {
    let ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (ip.includes(',')) ip = ip.split(',')[0].trim();
    ip = ip.replace('::ffff:', '').trim();
    if ((ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') && req.headers['x-forwarded-for']) {
        ip = req.headers['x-forwarded-for'].split(',')[0].trim();
    }
    req.clientIp = ip;
    if (req.path === '/mainPage' || req.path === '/mainPage.html') {
        if (!ip.startsWith('10.10.')) {
            return res.status(403).send(`
                <html><body style="font-family:sans-serif;text-align:center;padding:60px">
                <h2>🚫 Truy cập bị từ chối</h2>
                <div>Bạn cần kết nối VPN WireGuard để vào vùng quản trị.<br>
                IP hiện tại của bạn: <b>${ip}</b><br><br>
                <a href="/dashboard">Quay lại Dashboard để tải Key</a></div>
                </body></html>
            `);
        }
    }
    next();
});

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
    if (!ip) return 'unknown';
    if (ip.startsWith('10.10.10.')) return 'boss';
    if (ip.startsWith('10.10.20.')) return 'leader';
    if (ip.startsWith('10.10.30.')) return 'employee';
    return 'unknown';
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    connection.query(
        'SELECT name, role, google_auth_secret FROM users WHERE username = ? AND password = ?',
        [username, password],
        (err, results) => {
            if (err) return res.status(500).send('Database error.');
            if (results.length) {
                res.json({
                    mustVerify2FA: true,
                    hasSecret: !!results[0].google_auth_secret,
                    name: results[0].name,
                    role: results[0].role
                });
            } else {
                res.status(401).send('Invalid username or password');
            }
        }
    );
});

app.post('/api/setup-2fa', async (req, res) => {
    const { username } = req.body;
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(username, 'NoeruCryptoInc', secret);
    try {
        const imageUrl = await QRCode.toDataURL(otpauth);
        connection.query('UPDATE users SET google_auth_secret = ? WHERE username = ?', [secret, username], (err) => {
            if (err) return res.status(500).json({ error: 'Lỗi Database' });
            res.json({ qrCode: imageUrl });
        });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi tạo mã QR' });
    }
});

app.post('/api/verify-2fa', (req, res) => {
    const { username, token } = req.body;
    connection.query('SELECT google_auth_secret, name, role FROM users WHERE username = ?', [username], (err, results) => {
        if (err || !results.length) return res.status(500).json({ error: 'Lỗi xác thực' });
        const secret = results[0].google_auth_secret;
        const isValid = authenticator.check(token, secret);
        if (isValid) {
            res.json({ success: true, name: results[0].name, role: results[0].role });
        } else {
            res.status(401).json({ success: false });
        }
    });
});

app.get('/api/users', (req, res) => {
    const role = getRoleByIP(req.clientIp);
    if (role === 'employee' || role === 'unknown') {
        return res.status(403).json({ error: 'Quyền truy cập bị từ chối' });
    }
    connection.query('SELECT id, name, username, password, role, salary, extra FROM users', (err, results) => {
        if (err) return res.status(500).send('Database error.');
        if (role === 'leader') {
            results = results.map(u => ({ ...u, username: '********', password: '********' }));
        }
        res.json(results);
    });
});

app.post('/api/add-employee', async (req, res) => {
    const role = getRoleByIP(req.clientIp);
    if (role !== 'boss' && role !== 'leader') return res.status(403).json({ error: 'Quyền hạn thấp' });
    const { name, username, password, salary, extra } = req.body;
    try {
        const privateKey = await executeRouterCommand('wg genkey');
        const publicKey = await executeRouterCommand(`echo "${privateKey}" | wg pubkey`);
        connection.query(
            'INSERT INTO users (name, username, password, role, salary, extra, wg_private_key, wg_public_key) VALUES (?, ?, ?, "employee", ?, ?, ?, ?)',
            [name, username, password, salary, extra, privateKey, publicKey],
            async (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                const clientIp = `10.10.30.${result.insertId + 10}`;
                const allowedIps = `10.10.0.0/16, 192.168.2.0/24`;
                try {
                    await executeRouterCommand(`uci add network wireguard_wg0 && uci set network.@wireguard_wg0[-1].description='${name}' && uci set network.@wireguard_wg0[-1].public_key='${publicKey}' && uci add_list network.@wireguard_wg0[-1].allowed_ips='${clientIp}/32' && uci commit network && /etc/init.d/network reload && wg showconf wg0 > /etc/wireguard/wg0.conf`);
                    const config = `[Interface]\nPrivateKey = ${privateKey}\nAddress = ${clientIp}/32\nDNS = 10.10.10.1\n\n[Peer]\nPublicKey = 3P6hQGDLUnF+NWvOiLNBuOQxWPI0DnZ2zEVi6dfM1jM=\nEndpoint = vpn.noeruvpn.space:51820\nAllowedIPs = ${allowedIps}\nPersistentKeepalive = 25`;
                    fs.writeFileSync(path.join(__dirname, 'keys', `wg_${username}.conf`), config);
                    res.json({ message: 'Thành công', downloadLink: `/keys/wg_${encodeURIComponent(username)}.conf` });
                } catch { res.status(500).json({ error: 'Router error' }); }
            }
        );
    } catch { res.status(500).json({ error: 'System error' }); }
});

app.post('/api/edit-employee', async (req, res) => {
    if (getRoleByIP(req.clientIp) !== 'boss') return res.status(403).json({ error: 'Chỉ Boss' });
    const { id, name, username, password, role, salary, extra } = req.body;
    connection.query('SELECT wg_public_key, wg_private_key FROM users WHERE id = ?', [id], async (err, results) => {
        if (err || !results.length) return res.status(404).json({ error: 'Không tìm thấy' });
        const { wg_public_key, wg_private_key } = results[0];
        let newIp = `10.10.${role === 'boss' ? '10' : role === 'leader' ? '20' : '30'}.${parseInt(id) + 10}`;
        try {
            const idx = await executeRouterCommand(`uci show network | grep "${wg_public_key}" | cut -d'[' -f2 | cut -d']' -f1`);
            if (idx !== "") {
                await executeRouterCommand(`uci set network.@wireguard_wg0[${idx}].description='${name}' && uci set network.@wireguard_wg0[${idx}].allowed_ips='${newIp}/32' && uci commit network && /etc/init.d/network reload && wg showconf wg0 > /etc/wireguard/wg0.conf`);
            }
            const config = `[Interface]\nPrivateKey = ${wg_private_key}\nAddress = ${newIp}/32\nDNS = 10.10.10.1\n\n[Peer]\nPublicKey = 3P6hQGDLUnF+NWvOiLNBuOQxWPI0DnZ2zEVi6dfM1jM=\nEndpoint = vpn.noeruvpn.space:51820\nAllowedIPs = 10.10.0.0/16, 192.168.2.0/24\nPersistentKeepalive = 25`;
            fs.writeFileSync(path.join(__dirname, 'keys', `wg_${username}.conf`), config);
            let sql = 'UPDATE users SET name=?, username=?, role=?, salary=?, extra=?';
            let params = [name, username, role, salary, extra];
            if (password) { sql += ', password=?'; params.push(password); }
            sql += ' WHERE id=?'; params.push(id);
            connection.query(sql, params, () => res.json({ message: 'Cập nhật thành công' }));
        } catch { res.status(500).json({ error: 'Router error' }); }
    });
});

app.post('/api/delete-employee', async (req, res) => {
    if (getRoleByIP(req.clientIp) !== 'boss') return res.status(403).json({ error: 'Chỉ Boss' });
    const { id } = req.body;
    connection.query('SELECT wg_public_key, username FROM users WHERE id = ?', [id], async (err, results) => {
        if (err || !results.length) return res.status(404).json({ error: 'Không tồn tại' });
        try {
            const idx = await executeRouterCommand(`uci show network | grep "${results[0].wg_public_key}" | cut -d'[' -f2 | cut -d']' -f1`);
            if (idx !== "") {
                await executeRouterCommand(`uci delete network.@wireguard_wg0[${idx}] && uci commit network && /etc/init.d/network reload && wg showconf wg0 > /etc/wireguard/wg0.conf`);
            }
            const f = path.join(__dirname, 'keys', `wg_${results[0].username}.conf`);
            if (fs.existsSync(f)) fs.unlinkSync(f);
            connection.query('DELETE FROM users WHERE id = ?', [id], () => res.json({ message: 'Đã xóa' }));
        } catch { res.status(500).json({ error: 'SSH error' }); }
    });
});

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/mainPage', (req, res) => res.sendFile(path.join(__dirname, 'mainPage.html')));
app.get('/', (req, res) => res.redirect('/login'));

app.listen(port, () => console.log(`✅ Server running on port ${port}`));