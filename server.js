const express = require('express');
const mysql = require('mysql2');
const app = express();
const port = 3000;
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

app.use(express.static(__dirname));
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
        const privateKey = await executeRouterCommand('wg genkey');
        const publicKey = await executeRouterCommand(`echo "${privateKey}" | wg pubkey`);
        const sql = `INSERT INTO users (name, username, password, role, salary, extra, wg_private_key, wg_public_key)
                     VALUES (?, ?, ?, 'employee', ?, ?, ?, ?)`;
        connection.query(sql, [name, username, password, salary, extra, privateKey, publicKey], async (err, result) => {
            if (err) return res.status(500).json({ error: 'Lỗi Database' });
            const userId = result.insertId;
            const clientIp = `10.10.30.${userId + 10}`;
            const allowedIps = `10.10.30.0/24, 10.10.40.0/24`;
            try {
                await executeRouterCommand(`uci add network wireguard_wg0`);
                await executeRouterCommand(`uci set network.@wireguard_wg0[-1].description='${name}'`);
                await executeRouterCommand(`uci set network.@wireguard_wg0[-1].public_key='${publicKey}'`);
                await executeRouterCommand(`uci add_list network.@wireguard_wg0[-1].allowed_ips='${clientIp}/32'`);
                await executeRouterCommand(`uci commit network`);
                await executeRouterCommand(`/etc/init.d/network reload`);
                await executeRouterCommand(`wg showconf wg0 > /etc/wireguard/wg0.conf`);
                const configContent = `[Interface]
PrivateKey = ${privateKey}
Address = ${clientIp}/32
DNS = 1.1.1.1

[Peer]
PublicKey = 33jTKSv0WTnOxQoFgYHOsCUG7CS6qNPthn0ggKX743E=
Endpoint = 192.168.2.1:51820
AllowedIPs = ${allowedIps}
PersistentKeepalive = 25`;
                const fileName = `wg_${name}.conf`;
                const filePath = path.join(__dirname, 'keys', fileName);
                fs.writeFileSync(filePath, configContent);
                res.json({
                    message: 'Đã lưu vĩnh viễn vào Router và tạo file thành công!',
                    downloadLink: `/keys/${encodeURIComponent(fileName)}`
                });
            } catch (routerErr) {
                res.status(500).json({ error: 'Lỗi khi cấu hình Router' });
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Lỗi hệ thống Router' });
    }
});

app.post('/api/edit-employee', async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (getRoleByIP(clientIP) !== 'boss') {
        return res.status(403).json({ error: 'Chỉ Boss mới có quyền thay đổi chức vụ!' });
    }
    const { id, name, username, password, role, salary, extra } = req.body;
    try {
        connection.query('SELECT wg_public_key, wg_private_key FROM users WHERE id = ?', [id], async (err, results) => {
            if (err || results.length === 0) return res.status(404).json({ error: 'Không tìm thấy user' });
            const publicKey = results[0].wg_public_key;
            const privKey = results[0].wg_private_key;
            let newIpPrefix = '10.10.30';
            if (role === 'leader') newIpPrefix = '10.10.20';
            if (role === 'boss') newIpPrefix = '10.10.10';
            const newClientIp = `${newIpPrefix}.${parseInt(id) + 10}`;
            const allowedIps = `${newIpPrefix}.0/24, 10.10.40.0/24`;
            const index = await executeRouterCommand(`uci show network | grep "${publicKey}" | cut -d'[' -f2 | cut -d']' -f1`);
            if (index !== "") {
                await executeRouterCommand(`uci set network.@wireguard_wg0[${index}].description='${name}'`);
                await executeRouterCommand(`uci set network.@wireguard_wg0[${index}].allowed_ips='${newClientIp}/32'`);
                await executeRouterCommand(`uci commit network`);
                await executeRouterCommand(`/etc/init.d/network reload`);
                await executeRouterCommand(`wg showconf wg0 > /etc/wireguard/wg0.conf`);
            }
            const configContent = `[Interface]
PrivateKey = ${privKey}
Address = ${newClientIp}/32
DNS = 1.1.1.1

[Peer]
PublicKey = 33jTKSv0WTnOxQoFgYHOsCUG7CS6qNPthn0ggKX743E=
Endpoint = 192.168.2.1:51820
AllowedIPs = ${allowedIps}
PersistentKeepalive = 25`;
            const fileName = `wg_${name}.conf`;
            const filePath = path.join(__dirname, 'keys', fileName);
            fs.writeFileSync(filePath, configContent);
            let sql = 'UPDATE users SET name=?, username=?, role=?, salary=?, extra=?';
            let params = [name, username, role, salary, extra];
            if (password && password.trim() !== "") {
                sql += ', password=?';
                params.push(password);
            }
            sql += ' WHERE id=?';
            params.push(id);
            connection.query(sql, params, (dbErr) => {
                if (dbErr) return res.status(500).json({ error: 'Lỗi Database' });
                res.json({ message: `Đã cập nhật ${username} và IP ${newClientIp} thành công!` });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Lỗi cập nhật cấu hình Router' });
    }
});

app.post('/api/delete-employee', async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (getRoleByIP(clientIP) !== 'boss') {
        return res.status(403).json({ error: 'Chỉ Boss mới có quyền xóa nhân sự!' });
    }
    const { id } = req.body;
    connection.query('SELECT wg_public_key, username, name FROM users WHERE id = ?', [id], async (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ error: 'Nhân viên không tồn tại' });
        const { wg_public_key, username, name } = results[0];
        try {
            const index = await executeRouterCommand(`uci show network | grep "${wg_public_key}" | cut -d'[' -f2 | cut -d']' -f1`);
            if (index !== "") {
                await executeRouterCommand(`uci delete network.@wireguard_wg0[${index}]`);
                await executeRouterCommand(`uci commit network`);
                await executeRouterCommand(`/etc/init.d/network reload`);
                await executeRouterCommand(`wg showconf wg0 > /etc/wireguard/wg0.conf`);
            }
            const filePath = path.join(__dirname, 'keys', `wg_${name}.conf`);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            connection.query('DELETE FROM users WHERE id = ?', [id], (delErr) => {
                if (delErr) return res.status(500).json({ error: 'Lỗi Database khi xóa' });
                res.json({ message: `Đã thanh trừng [${username}] thành công!` });
            });
        } catch (sshError) {
            res.status(500).json({ error: 'Lỗi kết nối Router khi xóa' });
        }
    });
});

app.listen(port, () => {
    console.log(`✅ Server is running on http://localhost:${port}`);
});