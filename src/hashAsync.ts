import { HashFunction } from "./HashFunction";
import { NotSupportedError } from "@alumis/utils/src/NotSupportedError";

export function hashAsync(data: Uint8Array | string, hashFunction = HashFunction.RIPEMD160): Promise<Uint8Array> {

    if (hashFunction === HashFunction.RIPEMD160)
        return openpgp.crypto.hash.ripemd(typeof data === "string" ? openpgp.util.str_to_Uint8Array(data) : data);

    throw new NotSupportedError();
}