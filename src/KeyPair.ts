import { Key } from "./Key";

export class KeyPair {

    constructor(public publicKey: Key, public privateKey: Key) {

    }

    static async generateAsync() {

        let keys = await openpgp.generateKey({ userIds: [{ name: "" }], curve: "ed25519", passphrase: undefined });
        let publicKey = new Key();

        publicKey._OpenPGPKey = (await openpgp.key.readArmored(keys.publicKeyArmored)).keys[0];

        let privateKey = new Key();

        privateKey._OpenPGPKey = (await openpgp.key.readArmored(keys.privateKeyArmored)).keys[0];

        return new KeyPair(publicKey, privateKey);
    }
}