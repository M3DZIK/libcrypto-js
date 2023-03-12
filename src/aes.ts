import { Buffer } from "buffer"
import crypto from "crypto-browserify"

import * as salt from "./salt"

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
    const iv = salt.generate(16)

    // create a cipher using the secret key and the initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
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
    const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    // update decipher with the cipher text
    let clearText = cipher.update(cipherText, 'hex', 'utf8');
    // finalize decipher
    clearText += cipher.final()

    return clearText
}
