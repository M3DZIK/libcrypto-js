import { argon2, salt } from '.';

describe('argon2', () => {
    test('hash', async () => {
        const hash = await argon2.hash({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memory: 65536,
            parallelism: 1,
            type: argon2.Argon2id,
            password: 'password',
            salt: salt.generate(16),
        });

        expect(hash.encoded).toEqual(expect.any(String));
        expect(hash.hash).toEqual(expect.any(String));
    })

    test('check reproducibility', async () => {
        const inputSalt = salt.generate(16);
        const password = 'password';

        const hash1 = await argon2.hash({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memory: 65536,
            parallelism: 1,
            type: argon2.Argon2id,
            password,
            salt: inputSalt,
        });

        const hash2 = await argon2.hash({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memory: 65536,
            parallelism: 1,
            type: argon2.Argon2id,
            password,
            salt: inputSalt,
        });

        expect(hash1).toEqual(hash2);
    })

    test('valid hash', async () => {
        const hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ";

        await argon2.verify("medzik@duck.com", hash)
    })
})
