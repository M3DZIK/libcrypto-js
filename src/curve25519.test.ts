import { curve25519 } from "."
import { decryptAesGcm, encryptAesGcm } from "./aes";

describe("Curve25519", () => {
    test("Generate Key Pair", async () => {
        const keyPair = curve25519.generateKeyPair();

        expect(keyPair.privateKey).toHaveLength(64)
        expect(keyPair.publicKey).toHaveLength(64)
    })

    test("Calculate Agreement", async () => {
        const our = curve25519.generateKeyPair();
        const their = curve25519.generateKeyPair();

        const sharedSecret = curve25519.calculateAgreement(our.privateKey, their.publicKey);

        expect(sharedSecret).toHaveLength(64)
    })

    test("Calculate Agreement Encrypt", async () => {
        const keyPair = curve25519.generateKeyPair();

        const sharedSecret = curve25519.calculateAgreement(keyPair.privateKey, keyPair.publicKey);

        const cipherText = encryptAesGcm(sharedSecret, "hello world");

        const sharedSecret2 = curve25519.calculateAgreement(keyPair.privateKey, keyPair.publicKey);

        const plainText = decryptAesGcm(sharedSecret2, cipherText);

        expect(plainText).toBe("hello world")
    })

    test("Calculate Signature", async () => {
        const keyPair = curve25519.generateKeyPair();

        const signature = curve25519.calculateSignature(keyPair.privateKey, "hello world");

        expect(signature).toHaveLength(128)
    })

    test("Verify Signature", async () => {
        const keyPair = curve25519.generateKeyPair();

        const signature = curve25519.calculateSignature(keyPair.privateKey, "hello world");

        expect(curve25519.verifySignature(keyPair.publicKey, "hello world", signature)).toBeTruthy()
    })
})
