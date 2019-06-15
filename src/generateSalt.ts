import { Hash } from "./Hash";
import { NotSupportedError } from "@alumis/utils/src/NotSupportedError";

/** Returns a salt with an appropriate length according to the hash */
export function generateSalt(hash = Hash.RIPEMD160) {

    if (hash === Hash.RIPEMD160)
        return crypto.getRandomValues(new Uint8Array(20));

    throw new NotSupportedError();
}