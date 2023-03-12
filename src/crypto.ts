import _pbkdf2 from 'pbkdf2';
import aes from 'browserify-cipher';

export const pbkdf2 = _pbkdf2.pbkdf2;
export const pbkdf2Sync = _pbkdf2.pbkdf2Sync;

export const Cipher = aes.Cipher;
export const createCipher = aes.createCipher;
export const Cipheriv = aes.Cipheriv;
export const createCipheriv = aes.createCipheriv;
export const Decipher = aes.Decipher;
export const createDecipher = aes.createDecipher;
export const Decipheriv = aes.Decipheriv;
export const createDecipheriv = aes.createDecipheriv;
export const getCiphers = aes.getCiphers;
export const listCiphers = aes.listCiphers;
