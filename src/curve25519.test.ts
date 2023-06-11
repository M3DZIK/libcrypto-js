import { curve25519 } from "."
import { decryptAesGcm, encryptAesGcm } from "./aes";

describe("Curve25519", () => {
    test("Generate Key Pair", async () => {
        const keyPair = curve25519.generateKeyPair();

        expect(keyPair.privateKey).toHaveLength(64)
        expect(keyPair.publicKey).toHaveLength(64)
    })

    test("Calculate Shared Secret", async () => {
        const our = curve25519.generateKeyPair();
        const their = curve25519.generateKeyPair();

        const sharedSecret = curve25519.computeSharedSecret(our.privateKey, their.publicKey);

        expect(sharedSecret).toHaveLength(64)
    })

    test("Calculate Shared Secret Encrypt", async () => {
        const keyPair = curve25519.generateKeyPair();

        const sharedSecret = curve25519.computeSharedSecret(keyPair.privateKey, keyPair.publicKey);

        const cipherText = encryptAesGcm(sharedSecret, "hello world");

        const sharedSecret2 = curve25519.computeSharedSecret(keyPair.privateKey, keyPair.publicKey);

        const plainText = decryptAesGcm(sharedSecret2, cipherText);

        expect(plainText).toBe("hello world")
    })

    test("Recover Public Key", async () => {
        const keyPair = curve25519.generateKeyPair();

        const publicKey = curve25519.recoverPublicKey(keyPair.privateKey);

        expect(publicKey).toBe(keyPair.publicKey)
    })
})
