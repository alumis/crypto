import openpgp from "openpgp";

export class Key {

    _OpenPGPKey: openpgp.key.Key;

    get armor(): string {

        return this._OpenPGPKey.armor();
    }

    toUint8Array() {

        return <Uint8Array>this._OpenPGPKey.toPacketlist().write();
    }

    async toEncryptedUint8ArrayAsync(password: string) {

        var clone = (await openpgp.key.readArmored(this._OpenPGPKey.armor())).keys[0];

        await clone.encrypt(password);

        var key = new Key();

        key._OpenPGPKey = clone;

        return key.toUint8Array();
    }

    static async fromUint8ArrayAsync(plaintext: Uint8Array) {

        let result = new Key();

        result._OpenPGPKey = <openpgp.key.Key>(await openpgp.key.read(plaintext)).keys[0];

        return result;
    }

    static async fromEncryptedUint8ArrayAsync(ciphertext: Uint8Array, password: string) {

        let result = new Key();

        result._OpenPGPKey = <openpgp.key.Key>(await openpgp.key.read(ciphertext)).keys[0];

        await result._OpenPGPKey.decrypt(password);

        return result;
    }
}