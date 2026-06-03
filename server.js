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

app.use(express.json());

if (!fs.existsSync('./keys')) {
    fs.mkdirSync('./keys');
}

app.use((req, res, next) => {
    let ip = req.socket.remoteAddress || '';

    ip = ip.replace('::ffff:', '').trim();
    if (ip === '::1') ip = '127.0.0.1';

    if (ip === '127.0.0.1' || ip === 'localhost') {
        const xForwardedFor = req.headers['x-forwarded-for'];
        if (xForwardedFor) {
            ip = xForwardedFor.split(',')[0].trim().replace('::ffff:', '');
        } else {
            ip = req.headers['cf-connecting-ip'] || ip;
        }
    }

    req.clientIp = ip;

    if (req.path.startsWith('/mainPage')) {
        if (!ip.startsWith('10.10.')) {
            res.setHeader('Connection', 'close');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            return res.status(403).send(`
                <html>
                <head>
                    <title>🚫 Từ chối truy cập</title>
                    <script>
                        if (window.location.search) {
                            const cleanUrl = window.location.protocol + "//" + window.location.host + window.location.pathname;
                            window.history.replaceState({path: cleanUrl}, '', cleanUrl);
                        }
                    </script>
                </head>
                <body style="font-family:sans-serif;text-align:center;padding:60px">
                    <h2>🚫 Truy cập bị từ chối</h2>
                    <div>Bạn cần kết nối VPN WireGuard để vào vùng quản trị.<br>
                    IP hiện tại của bạn của bạn được hệ thống nhận diện là: <b style="color:red">${ip}</b><br><br>
                    <span style="font-size:14px;color:#555">Nếu IP trên không phải đầu số 10.10.x.x, nghĩa là gói tin chưa đi qua hầm VPN!</span><br><br>
                    <a href="/dashboard" style="display:inline-block;padding:10px 20px;background:#007bff;color:#fff;text-decoration:none;border-radius:4px">Quay lại Dashboard</a></div>
                </body>
                </html>
            `);
        }
    }
    next();
});

app.use(express.static(__dirname));
app.use('/keys', express.static(path.join(__dirname, 'keys')));

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
        res.json({ qrCode: imageUrl, secret: secret });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi tạo mã QR' });
    }
});

app.post('/api/verify-2fa', (req, res) => {
    const { username, token, secretFromSetup } = req.body;

    connection.query('SELECT id, google_auth_secret, name, role FROM users WHERE username = ?', [username], (err, results) => {
        if (err || !results.length) return res.status(500).json({ error: 'Lỗi xác thực' });

        const secret = results[0].google_auth_secret || secretFromSetup;

        if (!secret) return res.status(400).json({ error: 'Thiếu thông số cấu hình 2FA' });

        const isValid = authenticator.check(token, secret);
        if (isValid) {
            const userId = results[0].id;
            connection.query('INSERT INTO logs (user_id, action, ip_address) VALUES (?, "2FA Verification Success", ?)', [userId, req.clientIp]);

            if (!results[0].google_auth_secret) {
                connection.query('UPDATE users SET google_auth_secret = ? WHERE username = ?', [secret, username], (updateErr) => {
                    if (updateErr) return res.status(500).json({ error: 'Lỗi kích hoạt 2FA vào DB' });
                    res.json({ success: true, name: results[0].name, role: results[0].role });
                });
            } else {
                res.json({ success: true, name: results[0].name, role: results[0].role });
            }
        } else {
            res.status(401).json({ success: false, message: "Mã xác thực không chính xác" });
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
        const keysOutput = await executeRouterCommand(`priv=$(wg genkey) && pub=$(echo "$priv" | wg pubkey) && echo "$priv|$pub"`);
        const [privateKey, publicKey] = keysOutput.trim().split('|');

        connection.query(
            'INSERT INTO users (name, username, password, role, salary, extra) VALUES (?, ?, ?, "employee", ?, ?)',
            [name, username, password, salary, extra],
            async (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error khi khoi tao user' });

                const userId = result.insertId;
                const clientIp = `10.10.30.${userId + 10}`;
                const allowedIps = `10.10.0.0/16`;

                connection.query(
                    'INSERT INTO vpn_configs (user_id, client_ip, wg_private_key, wg_public_key) VALUES (?, ?, ?, ?)',
                    [userId, clientIp, privateKey, publicKey],
                    async (vpnErr) => {
                        if (vpnErr) return res.status(500).json({ error: 'VPN storage error khi luu cấu hinh' });

                        try {
                            const routerCmd = `wg set wg0 peer '${publicKey}' allowed-ips '${clientIp}/32'; uci add network wireguard_wg0 && uci set network.@wireguard_wg0[-1].description='${name}' && uci set network.@wireguard_wg0[-1].public_key='${publicKey}' && uci add_list network.@wireguard_wg0[-1].allowed_ips='${clientIp}/32' && uci commit network && wg showconf wg0 > /etc/wireguard/wg0.conf`;
                            await executeRouterCommand(routerCmd);

                            const config = `[Interface]\nPrivateKey = ${privateKey}\nAddress = ${clientIp}/32\nDNS = 10.10.10.1\n\n[Peer]\nPublicKey = 3P6hQGDLUnF+NWvOiLNBuOQxWPI0DnZ2zEVi6dfM1jM=\nEndpoint = vpn.noeruvpn.space:51820\nAllowedIPs = ${allowedIps}\nPersistentKeepalive = 25`;
                            fs.writeFileSync(path.join(__dirname, 'keys', `wg_${username}.conf`), config);

                            return res.json({ message: 'Tạo tài khoản thành công', downloadLink: `/keys/wg_${encodeURIComponent(username)}.conf` });
                        } catch (routerErr) {
                            return res.status(500).json({ error: 'Lỗi Router' });
                        }
                    }
                );
            }
        );
    } catch (sysErr) {
        return res.status(500).json({ error: 'Lỗi hệ thống' });
    }
});

app.post('/api/edit-employee', async (req, res) => {
    if (getRoleByIP(req.clientIp) !== 'boss') return res.status(403).json({ error: 'Chỉ Boss' });
    const { id, name, username, password, role, salary, extra } = req.body;

    connection.query('SELECT wg_public_key, wg_private_key FROM vpn_configs WHERE user_id = ?', [id], async (err, results) => {
        if (err || !results.length) return res.status(404).json({ error: 'Không tìm thấy cấu hình VPN' });
        const { wg_public_key, wg_private_key } = results[0];
        let newIp = `10.10.${role === 'boss' ? '10' : role === 'leader' ? '20' : '30'}.${parseInt(id) + 10}`;

        try {
            const idx = await executeRouterCommand(`uci show network | grep "${wg_public_key}" | cut -d'[' -f2 | cut -d']' -f1`);
            if (idx !== "") {
                const routerCmd = `wg set wg0 peer '${wg_public_key}' allowed-ips '${newIp}/32'; uci set network.@wireguard_wg0[${idx}].description='${name}' && uci set network.@wireguard_wg0[${idx}].allowed_ips='${newIp}/32' && uci commit network && wg showconf wg0 > /etc/wireguard/wg0.conf`;
                await executeRouterCommand(routerCmd);
            }

            const config = `[Interface]\nPrivateKey = ${wg_private_key}\nAddress = ${newIp}/32\nDNS = 10.10.10.1\n\n[Peer]\nPublicKey = 3P6hQGDLUnF+NWvOiLNBuOQxWPI0DnZ2zEVi6dfM1jM=\nEndpoint = vpn.noeruvpn.space:51820\nAllowedIPs = 10.10.0.0/16\nPersistentKeepalive = 25`;
            fs.writeFileSync(path.join(__dirname, 'keys', `wg_${username}.conf`), config);

            connection.query(
                'UPDATE vpn_configs SET client_ip = ? WHERE user_id = ?',
                [newIp, id],
                () => {
                    let sql = 'UPDATE users SET name=?, username=?, role=?, salary=?, extra=?';
                    let params = [name, username, role, salary, extra];
                    if (password) { sql += ', password=?'; params.push(password); }
                    sql += ' WHERE id=?'; params.push(id);
                    connection.query(sql, params, () => {
                        return res.json({ message: 'Cập nhật thành công hệ thống nhân sự và cấu hình mạng' });
                    });
                }
            );
        } catch {
            return res.status(500).json({ error: 'Router error configuration' });
        }
    });
});

app.post('/api/delete-employee', async (req, res) => {
    if (getRoleByIP(req.clientIp) !== 'boss') return res.status(403).json({ error: 'Chỉ Boss' });
    const { id } = req.body;

    connection.query('SELECT wg_public_key FROM vpn_configs WHERE user_id = ?', [id], async (err, results) => {
        if (err || !results.length) return res.status(404).json({ error: 'Không tồn tại cấu hình VPN' });

        connection.query('SELECT username FROM users WHERE id = ?', [id], async (userErr, userRes) => {
            if (userErr || !userRes.length) return res.status(404).json({ error: 'Không tồn tại người dùng' });

            try {
                const idx = await executeRouterCommand(`uci show network | grep "${results[0].wg_public_key}" | cut -d'[' -f2 | cut -d']' -f1`);
                if (idx !== "") {
                    const routerCmd = `wg set wg0 peer '${results[0].wg_public_key}' remove 2>/dev/null; uci delete network.@wireguard_wg0[${idx}] && uci commit network && wg showconf wg0 > /etc/wireguard/wg0.conf`;
                    await executeRouterCommand(routerCmd);
                } else {
                    await executeRouterCommand(`wg set wg0 peer '${results[0].wg_public_key}' remove 2>/dev/null; wg showconf wg0 > /etc/wireguard/wg0.conf`).catch(() => {});
                }

                const f = path.join(__dirname, 'keys', `wg_${userRes[0].username}.conf`);
                if (fs.existsSync(f)) fs.unlinkSync(f);

                connection.query('DELETE FROM users WHERE id = ?', [id], (deleteErr) => {
                    if (deleteErr) return res.status(500).json({ error: 'Database delete error' });
                    return res.json({ message: 'Đã xóa hoàn toàn' });
                });
            } catch {
                return res.status(500).json({ error: 'SSH error' });
            }
        });
    });
});

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/mainPage', (req, res) => res.sendFile(path.join(__dirname, 'mainPage.html')));
app.get('/', (req, res) => res.redirect('/login'));

const { exec } = require('child_process');

const blockedIPs = new Set();
const isValidIP = (ip) => {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
};

app.post('/api/report-attack', async (req, res) => {
    const { attacker_ip, attack_type, packet_rate } = req.body;

    // --- KIỂM TRA ĐẦU VÀO ---
    if (!attacker_ip || !isValidIP(attacker_ip)) {
        console.log(`[!] Cảnh báo: Nhận được IP không hợp lệ từ AI: ${attacker_ip}`);
        return res.status(400).json({ error: "Invalid Attacker IP format" });
    }

    // --- KIỂM TRA CHỐNG SPAM ---
    if (blockedIPs.has(attacker_ip)) {
        return res.json({ status: "ignored", message: "IP is already blocked." });
    }

    blockedIPs.add(attacker_ip);

    // --- IN LOG GIAO DIỆN ---
    console.log(`\n[ALARM - HỆ THỐNG HYBRID IDS PHÁT HIỆN TẤN CÔNG]`);
    console.log(`> Kẻ tấn công : ${attacker_ip}`);
    console.log(`> Phân loại   : ${attack_type || 'Unknown Type'}`);
    console.log(`> Tốc độ      : ${packet_rate || 0} gói/s`);

    // --- THỰC THI LỆNH CÁCH LY CHỐNG XÂM NHẬP ---
    try {
        if (attacker_ip.startsWith('10.10.')) {
            // Xử lý chặn trên Firewall Router (mạng nội bộ)
            const cmd = `iptables -I INPUT -s ${attacker_ip} -j DROP`;
            await executeRouterCommand(cmd);
            console.log(`[✔ IPS] Đã cách ly IP nội bộ: ${attacker_ip} trên Firewall Router.`);
            return res.json({ status: "success", message: "Router isolated successfully" });

        } else {
            // Xử lý chặn trên Windows Firewall (vãng lai)
            const blockCmd = `netsh advfirewall firewall add rule name="AI_Block_${attacker_ip}" dir=in action=block remoteip=${attacker_ip}`;

            exec(blockCmd, (error) => {
                if (error) {
                    console.error(`[x Lỗi Windows Firewall]: ${error.message}`);
                    blockedIPs.delete(attacker_ip);
                } else {
                    console.log(`[✔ IPS] Đã tống cổ IP vãng lai: ${attacker_ip} bằng Windows Firewall.`);
                }
            });
            return res.json({ status: "success", message: "Windows Host isolated" });
        }
    } catch (error) {
        console.error(`[x Lỗi thực thi hệ thống phòng vệ]:`, error);
        blockedIPs.delete(attacker_ip);
        res.status(500).json({ error: "Lỗi thực thi hệ thống phòng vệ" });
    }
});

app.listen(port, '0.0.0.0', () => console.log(`✅ Server running on IPv4 port ${port}`));