import { BinaryLike, pbkdf2Sync } from "crypto-browserify";

/**
 * Hashes a password using PBKDF2-SHA256.
 * @param password Password to hash.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns Hash of the password.
 */
export function hash256(password: string, salt: BinaryLike, iterations: number): string {
  return pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex");
}

/**
 * Hashes a password using PBKDF2-SHA512.
 * @param password Password to hash.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns Hash of the password.
 */
export function hash512(password: string, salt: BinaryLike, iterations: number): string {
  return pbkdf2Sync(password, salt, iterations, 64, "sha512").toString("hex");
}

/**
 * Hashes and verifies a password using PBKDF2-SHA256.
 * @param hash Expected hash.
 * @param password Password to check.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns If the password matches the hash.
 */
export function match256(hash: string, password: string, salt: BinaryLike, iterations: number): boolean {
  return hash256(password, salt, iterations) === hash;
}

/**
 * Hashes and verifies a password using PBKDF2-SHA512.
 * @param hash Expected hash.
 * @param password Password to check.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns If the password matches the hash.
 */
export function match512(hash: string, password: string, salt: BinaryLike, iterations: number): boolean {
  return hash512(password, salt, iterations) === hash;
}
