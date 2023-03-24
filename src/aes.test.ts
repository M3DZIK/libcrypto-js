import { aes, pbkdf2 } from "."

describe("AES", () => {
    test("Encrypt and Decrypt", async () => {
        const clearText = "hello world"
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)

        const cipherText = aes.encryptAesCbc(secretKey, clearText)

        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe(clearText)
    })

    test("Decrypt", async () => {
        const salt = "salt"
        const secretKey = await pbkdf2.hash256("secret passphrase", salt, 1000)
        const cipherText = "ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d"

        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe("hello world")
    })
})
