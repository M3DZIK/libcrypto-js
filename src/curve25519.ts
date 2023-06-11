import { Buffer } from "buffer/"
import * as curve25519 from "@stablelib/x25519"

/**
 * Generate a new Curve25519 key pair.
 */
export function generateKeyPair() {
    const keyPair = curve25519.generateKeyPair();

    return {
        privateKey: bytesToHex(keyPair.secretKey),
        publicKey: bytesToHex(keyPair.publicKey)
    }
}

/**
 * Calculate a shared secret given our private key and their public key.
 * @param ourPrivate our private key
 * @param theirPublic their public key
 * @return Shared secret.
 */
export function computeSharedSecret(ourPrivate: string, theirPublic: string) {
    const sharedSecret = curve25519.sharedKey(hexToBuffer(ourPrivate), hexToBuffer(theirPublic));

    return bytesToHex(sharedSecret);
}

/**
 * Recover the public key from a private key.
 * @param privateKey private key
 * @return Public key.
 */
export function recoverPublicKey(privateKey: string) {
    const publicKey = curve25519.scalarMultBase(hexToBuffer(privateKey));

    return bytesToHex(publicKey);
}

function hexToBuffer(hex: string) {
    return Buffer.from(hex, 'hex');
}

function bytesToHex(bytes: Uint8Array) {
    return Buffer.from(bytes).toString('hex');
}
