import { aes, pbkdf2 } from "."

describe("AES", () => {
    test("CBC Encrypt and Decrypt", async () => {
        const clearText = "hello world"
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)

        const cipherText = aes.encryptAesCbc(secretKey, clearText)

        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe(clearText)
    })

    test("CBC Decrypt", async () => {
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)
        const cipherText = "ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d"

        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe("hello world")
    })

    test("GCM Encrypt and Decrypt", async () => {
        const clearText = "hello world"
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)

        const cipherText = aes.encryptAesGcm(secretKey, clearText)

        const decryptedText = aes.decryptAesGcm(secretKey, cipherText)

        expect(decryptedText).toBe(clearText)
    })

    test("GCM Decrypt", async () => {
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)
        const cipherText = "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d"

        const decryptedText = aes.decryptAesGcm(secretKey, cipherText)

        expect(decryptedText).toBe("hello world")
    })
})
