const { encrypt, decrypt } = require('./script.js');

// Example payload
const userPayload = { id: 1, name: 'John Doe', role: 'admin' };

// Encrypt JWT
const encryptedToken = encrypt(userPayload);
console.log('🔐 Encrypted Token:', encryptedToken);

// Decrypt JWT
try {
    const decryptedData = decrypt(encryptedToken);
    console.log('🔓 Decrypted Data:', decryptedData);
} catch (error) {
    console.error('❌ Error:', error.message);
}
