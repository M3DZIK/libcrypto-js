import keygen from 'browser-keygen';
import { publicEncrypt, privateDecrypt } from "public-encrypt";

/**
 * Generate RSA key pair using browserify-rsa
 * @param bitLength - Bit length of the key pair
 * @returns RSA key pair (public key and private key)
 */
export async function generateKeyPair(bitLength: number): Promise<{ publicKey: string, privateKey: string }> {
    return new Promise((resolve, reject) => {
        keygen.generateKeyPair('rsa', {
            modulusLength: bitLength,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs1',
                format: 'pem'
            }
        }, (err, publicKey, privateKey) => {
            if (err) reject(err)

            resolve({
                publicKey: publicKey,
                privateKey: privateKey
            })
        })
    });
}

/**
 * Encrypt data using RSA public key
 * @param data - Data to encrypt
 * @param publicKey - RSA public key
 */
export async function encrypt(data: string, publicKey: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const encryptedData = publicEncrypt(publicKey, Buffer.from(data));
        resolve(encryptedData.toString("base64"));
    });
}

/**
 * Decrypt data using RSA private key
 * @param encryptedData - Encrypted data
 * @param privateKey - RSA private key
 * @returns Decrypted data
 */
export async function decrypt(encryptedData: string, privateKey: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const decryptedData = privateDecrypt({
            key: privateKey
        }, Buffer.from(encryptedData, "base64"));
        resolve(decryptedData.toString());
    });
}
