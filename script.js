const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;

// Encrypt function
const encrypt = (payload) => {
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(token);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Decrypt function
const decrypt = (token) => {
    let parts = token.split(':');
    let iv = Buffer.from(parts.shift(), 'hex');
    let encryptedText = Buffer.from(parts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return jwt.verify(decrypted.toString(), SECRET_KEY);
};

module.exports = { encrypt, decrypt };