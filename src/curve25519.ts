import { Buffer } from "buffer/"
import * as curve25519 from 'curve25519-js';

import { generate as salt } from "./salt"

/**
 * Generate a new Curve25519 key pair.
 */
export function generateKeyPair() {
    const seed = salt(32);

    const keyPair = curve25519.generateKeyPair(seed);

    return {
        privateKey: bytesToHex(keyPair.private),
        publicKey: bytesToHex(keyPair.public)
    }
}

/**
 * Calculate a shared secret given our private key and their public key.
 * @param ourPrivate our private key
 * @param theirPublic their public key
 * @return Shared secret.
 */
export function calculateAgreement(ourPrivate: string, theirPublic: string) {
    const sharedSecret = curve25519.sharedKey(hexToBuffer(ourPrivate), hexToBuffer(theirPublic));

    return bytesToHex(sharedSecret);
}

/**
 * Calculate a Curve25519 signature given a private key and a message.
 * @param privateKey private key to signing
 * @param message message to sign (hex encoded)
 * @return Curve25519 signature.
 */
export function calculateSignature(privateKey: string, message: string) {
    const signature = curve25519.sign(hexToBuffer(privateKey), hexToBuffer(message), salt(64));

    return bytesToHex(signature);
}

/**
 * Verify a Curve25519 signature given a public key, message, and signature.
 * @param publicKey public key to verify
 * @param message message to verify (hex encoded)
 * @param signature signature to verify
 * @return True if the signature is valid, false otherwise.
 */
export function verifySignature(publicKey: string, message: string, signature: string) {
    return curve25519.verify(hexToBuffer(publicKey), hexToBuffer(message), hexToBuffer(signature));
}

function hexToBuffer(hex: string) {
    return Buffer.from(hex, 'hex');
}

function bytesToHex(bytes: Uint8Array) {
    return Buffer.from(bytes).toString('hex');
}
