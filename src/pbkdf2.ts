import { pbkdf2 } from "./crypto";

/**
 * Hashes a password using PBKDF2-SHA256.
 * @param password Password to hash.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns Hash of the password.
 */
export async function hash256(password: string, salt: any, iterations: number): Promise<string> {
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, 32, "sha256", (err, key) => {
      if (err) {
        reject(err);
      } else {
        resolve(key.toString("hex"));
      }
    });
  });
}

/**
 * Hashes a password using PBKDF2-SHA512.
 * @param password Password to hash.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns Hash of the password.
 */
export async function hash512(password: string, salt: any, iterations: number): Promise<string> {
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, 64, "sha512", (err, key) => {
      if (err) {
        reject(err);
      } else {
        resolve(key.toString("hex"));
      }
    });
  });
}

/**
 * Hashes and verifies a password using PBKDF2-SHA256.
 * @param hash Expected hash.
 * @param password Password to check.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns If the password matches the hash.
 */
export async function match256(hash: string, password: string, salt: any, iterations: number): Promise<boolean> {
  return (await hash256(password, salt, iterations)) === hash;
}

/**
 * Hashes and verifies a password using PBKDF2-SHA512.
 * @param hash Expected hash.
 * @param password Password to check.
 * @param salt Salt to use for hashing.
 * @param iterations Number of hashing iterations.
 * @returns If the password matches the hash.
 */
export async function match512(hash: string, password: string, salt: any, iterations: number): Promise<boolean> {
  return (await hash512(password, salt, iterations)) === hash;
}
