import { Buffer } from 'buffer/';
import argon2 from 'argon2-browser';

export const Argon2d = argon2.ArgonType.Argon2d;
export const Argon2i = argon2.ArgonType.Argon2i;
export const Argon2id = argon2.ArgonType.Argon2id;

/**
 * Options for the Argon2 hash function.
 * @see {@link hash}
 */
export type Argon2Options = {
    hashLength: number,
    parallelism: number,
    memory: number,
    iterations: number,
    type: argon2.ArgonType,
    password: string,
    salt: string | Buffer,
}

/**
 * The result of the Argon2 hash function.
 */
export type Argon2Hash = {
    encoded: string,
    hash: string,
}

function bytesToHex(bytes) {
    let hex = [];
    for (let i = 0; i < bytes.length; i++) {
        let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

/**
 * Hashes a password using Argon2.
 * @param options The options for the Argon2 hash function.
 */
export async function hash(options: Argon2Options): Promise<Argon2Hash> {
    const hash = await argon2.hash({
        pass: options.password,
        salt: options.salt,
        time: options.iterations,
        mem: options.memory,
        hashLen: options.hashLength,
        parallelism: options.parallelism,
        type: options.type,
    });

    return {
        encoded: hash.encoded,
        hash: bytesToHex(hash.hash),
    }
}

/**
 * Verifies a password against a hash.
 * @param password The password to verify.
 * @param hash The hash to verify against.
 */
export async function verify(password: string, hash: string): Promise<boolean> {
    return await argon2.verify({
        pass: password,
        encoded: hash,
    });
}
