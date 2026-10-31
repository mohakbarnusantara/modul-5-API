const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USER_FILE = path.join(__dirname, 'data', 'users.json');
const ROLE_SAH = ['admin', 'editor'];

const [username, password, role] = process.argv.slice(2);

if (!username || !password || !ROLE_SAH.includes(role)) {
  console.log('Cara pakai: node buat-user.js <username> <password> <admin|editor>');
  process.exit(1);
}

let users = [];
if (fs.existsSync(USER_FILE)) {
  users = JSON.parse(fs.readFileSync(USER_FILE, 'utf8'));
}

if (users.some((u) => u.username === username)) {
  console.log(`Username ${username} sudah terdaftar`);
  process.exit(1);
}

const salt = crypto.randomBytes(16).toString('hex');
const passwordHash = crypto.scryptSync(password, salt, 32).toString('hex');
const idBaru = users.length === 0 ? 1 : Math.max(...users.map((u) => u.id)) + 1;

users.push({
  id: idBaru,
  username: username,
  role: role,
  salt: salt,
  passwordHash: passwordHash
});

fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));
console.log(`User ${username} dengan role ${role} berhasil dibuat`);