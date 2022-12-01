import { salt } from ".";

test("Generate random salt", () => {
    expect(salt.generate(16)).toHaveLength(16);
})
