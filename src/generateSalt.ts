import { HashFunction } from "./HashFunction";
import { NotSupportedError } from "@alumis/utils/src/NotSupportedError";

/** Returns a salt with an appropriate length according to the hash */
export function generateSalt(hashFunction = HashFunction.RIPEMD160) {

    if (hashFunction === HashFunction.RIPEMD160)
        return crypto.getRandomValues(new Uint8Array(20));

    throw new NotSupportedError();
}