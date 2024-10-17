const crypto = require('crypto');


const generateSecretKey = () => {
    const secretKey = crypto.randomBytes(64).toString('hex');
    return secretKey;
};

module.exports = generateSecretKey;
