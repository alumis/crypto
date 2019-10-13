export class Key {

    _OpenPGPKey: openpgp.key.Key;

    get armor(): string {
        return this._OpenPGPKey.armor();
    }

    toUint8Array() {
        return <Uint8Array>this._OpenPGPKey.toPacketlist().write();
    }

    async toEncryptedUint8ArrayAsync(password: string) {
        let clone = (await openpgp.key.readArmored(this._OpenPGPKey.armor())).keys[0];
        await clone.encrypt(password);
        let key = new Key();
        key._OpenPGPKey = clone;
        return key.toUint8Array();
    }

    async toAsymmetricallyEncryptedUint8ArrayAsync(publicKey: Key) {
        let plaintext = this.toUint8Array();
        return <Uint8Array>(await openpgp.encrypt({ message: openpgp.message.fromBinary(plaintext), publicKeys: publicKey._OpenPGPKey, armor: false })).message.packets.write();
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

    static async fromAsymmetricallyEncryptedUint8ArrayAsync(ciphertext: Uint8Array, privateKey: Key) {
        let message = await openpgp.message.read(ciphertext);
        let plaintext = <Uint8Array>(await openpgp.decrypt({ message: message, privateKeys: privateKey._OpenPGPKey, format: "binary" })).data;
        let result = new Key();
        result._OpenPGPKey = <openpgp.key.Key>(await openpgp.key.read(plaintext)).keys[0];
        return result;
    }
}