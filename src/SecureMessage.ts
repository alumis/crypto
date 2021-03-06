import { Key } from "./Key";
import { KeyPair } from "./KeyPair";
import { Signature } from "./Signature";
import { encode, decode } from "@alumis/utils/src/msgpack";

export class SecureMessage<T> {

    constructor(public cleartext?: T) {
        
    }

    signature: Signature;

    private _plaintext: Uint8Array;

    async signAsync(sendersKeyPair: KeyPair) {

        if (!this._plaintext)
            this._plaintext = encode(this.cleartext);

        let signature = new Signature();
        let message = openpgp.message.fromBinary(this._plaintext);

        signature._OpenPGPSignature = await openpgp.signature.readArmored((await openpgp.sign({ message: message, privateKeys: sendersKeyPair.privateKey._OpenPGPKey, detached: true })).signature);
        signature.sendersPublicKey = sendersKeyPair.publicKey;
        signature.isVerified = true;

        this.signature = signature;
    }

    async ensureAuthenticityAsync(sendersPublicKey: Key) {

        if (sendersPublicKey) {

            let signature = this.signature;

            if (signature) {

                if (signature.isVerified && signature.sendersPublicKey === sendersPublicKey)
                    return;

                signature.isVerified = false;
                signature.sendersPublicKey = sendersPublicKey;

                await signature.ensureIsVerifiedAsync(this._plaintext);
            }

            else console.warn("Unable to ensure authenticity of possibly signed message because there is no signature to verify against");
        }

        else console.warn("Unable to ensure authenticity of possibly signed message because there is no public key to verify against");
    }

    async toAsymmetricallyEncryptedUint8ArrayAsync(recipientsPublicKey: Key) {

        if (!this._plaintext)
            this._plaintext = encode(this.cleartext);

        let signature = this.signature;
        let plaintextAndSignature = encode([this._plaintext, signature ? signature.toUint8Array() : null]);
        let ciphertext = <Uint8Array>(await openpgp.encrypt({ message: openpgp.message.fromBinary(plaintextAndSignature), publicKeys: recipientsPublicKey._OpenPGPKey, armor: false })).message.packets.write();

        return ciphertext;
    }

    async toSymmetricallyEncryptedUint8ArrayAsync(password: string) {

        if (!this._plaintext)
            this._plaintext = encode(this.cleartext);

        let signature = this.signature;
        let plaintextAndSignature = encode([this._plaintext, signature ? signature.toUint8Array() : null]);
        let ciphertext = <Uint8Array>(await openpgp.encrypt({ message: openpgp.message.fromBinary(plaintextAndSignature), passwords: password, armor: false })).message.packets.write();

        return ciphertext;
    }

    static async fromAsymmetricallyEncryptedUint8ArrayAsync<T>(ciphertext: Uint8Array, recipientsPrivateKey: Key) {

        let message = await openpgp.message.read(ciphertext);
        let plaintextAndSignature = decode(<Uint8Array>(await openpgp.decrypt({ message: message, privateKeys: recipientsPrivateKey._OpenPGPKey, format: "binary" })).data) as Array<any>;
        let result = new SecureMessage<T>();

        result.cleartext = decode(result._plaintext = plaintextAndSignature[0]) as T;

        if (plaintextAndSignature[1])
            result.signature = await Signature.fromUint8ArrayAsync(plaintextAndSignature[1]);

        return result;
    }

    static async fromSymmetricallyEncryptedUint8ArrayAsync<T>(ciphertext: Uint8Array, password: string) {

        let message = await openpgp.message.read(ciphertext);
        let plaintextAndSignature = decode(<Uint8Array>(await openpgp.decrypt({ message: message, passwords: password, format: "binary" })).data) as Array<any>;
        let result = new SecureMessage<T>();

        result.cleartext = decode(result._plaintext = plaintextAndSignature[0]) as T;

        if (plaintextAndSignature[1])
            result.signature = await Signature.fromUint8ArrayAsync(plaintextAndSignature[1]);

        return result;
    }
}