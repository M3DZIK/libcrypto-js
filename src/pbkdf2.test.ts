import { pbkdf2 } from "."

describe("PBKDF2", () => {
    test("SHA-256", async () => {
        const salt = "salt"
        const iterations = 1000

        const hash = await pbkdf2.hash256("hello world", salt, iterations)

        expect(hash).toBe("27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def")
    })

    test("SHA-512", async () => {
        const salt = "salt"
        const iterations = 1000

        const hash = await pbkdf2.hash512("hello world", salt, iterations)

        expect(hash).toBe("883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9")
    })

    test("SHA-256 match", async () => {
        const salt = "salt"
        const iterations = 1000

        const matched = await pbkdf2.match256("27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def", "hello world", salt, iterations)

        expect(matched).toBe(true)
    })

    test("SHA-512 match", async () => {
        const salt = "salt"
        const iterations = 1000

        const matched = await pbkdf2.match512("883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9", "hello world", salt, iterations)

        expect(matched).toBe(true)
    })
})
