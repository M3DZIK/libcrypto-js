import { Buffer } from "buffer/"

import { createCipheriv, createDecipheriv } from "./crypto"
import { generate as salt } from "./salt"

/**
 * Encrypts the clear text using AES-256-CBC algorithm
 * @param secretKey The secret key to encrypt the data.
 * @param clearText The data to encrypt.
 * @returns The encrypted data as a hex string.
 */
export function encryptAesCbc(secretKey: string, clearText: string): string {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // generate a random initialization vector
    const iv = salt(16)

    // create a cipher using the secret key and the initialization vector
    const cipher = createCipheriv('aes-256-cbc', key, iv)
    // update the cipher with the clear text
    let cipherText = cipher.update(clearText, 'utf8', 'hex')
    // finalize the cipher
    cipherText += cipher.final('hex')

    // add the initialization vector to the cipher text
    cipherText = Buffer.from(iv).toString('hex') + cipherText

    return cipherText
}

/**
 * Decrypts the cipher text using AES-256-CBC algorithm
 * @param secretKey The secret key to decrypt the data.
 * @param cipherText The data to decrypt.
 * @returns The decrypted data as a string.
 */
export function decryptAesCbc(secretKey: string, cipherText: string): string {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // get the initialization vector from the cipher text
    const iv = Buffer.from(cipherText.substring(0, 32), 'hex')
    // remove the initialization vector from the cipher text
    cipherText = cipherText.substring(32)

    // create decipher using the secret key and the initialization vector
    const cipher = createDecipheriv('aes-256-cbc', key, iv)
    // update decipher with the cipher text
    let clearText = cipher.update(cipherText, 'hex', 'utf8');
    // finalize decipher
    clearText += cipher.final()

    return clearText
}

/**
 * Encrypts the clear text using AES-256-GCM algorithm
 * @param secretKey The secret key to encrypt the data.
 * @param clearText The data to encrypt.
 * @returns The encrypted data as a hex string.
 */
export function encryptAesGcm(secretKey: string, clearText: string): string {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // generate a random initialization vector
    const iv = salt(12)

    // create a cipher using the secret key and the initialization vector
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    // update the cipher with the clear text
    let cipherText = cipher.update(clearText, 'utf8', 'hex')
    // finalize the cipher
    cipherText += cipher.final('hex')

    // add the initialization vector and the auth tag to the cipher text
    cipherText = Buffer.from(iv).toString('hex') + cipherText + cipher.getAuthTag().toString('hex')

    return cipherText
}

/**
 * Decrypts the cipher text using AES-256-GCM algorithm
 * @param secretKey The secret key to decrypt the data.
 * @param cipherText The data to decrypt.
 * @returns The decrypted data as a string.
 */
export function decryptAesGcm(secretKey: string, cipherText: string): string {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // get the initialization vector from the cipher text
    const iv = Buffer.from(cipherText.substring(0, 24), 'hex')
    // remove the initialization vector from the cipher text
    cipherText = cipherText.substring(24)
    // get the auth tag from the cipher text
    const authTag = Buffer.from(cipherText.substring(cipherText.length - 32), 'hex')
    // remove the auth tag from the cipher text
    cipherText = cipherText.substring(0, cipherText.length - 32)

    // create decipher using the secret key and the initialization vector
    const cipher = createDecipheriv('aes-256-gcm', key, iv)
    cipher.setAuthTag(authTag)

    // update decipher with the cipher text
    let clearText = cipher.update(cipherText, 'hex', 'utf8');
    // finalize decipher
    clearText += cipher.final()

    return clearText
}
