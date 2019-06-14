import { uint8ArrayToHex } from "@alumis/utils/src/uint8ArrayToHex";
import { Key } from "./Key";
import { SignatureVerificationFailedError } from "./SignatureVerificationFailedError";

export class Signature {

    sendersPublicKey = null as Key;
    isVerified = false;

    _OpenPGPSignature: openpgp.signature.Signature;

    get created() {

        return <Date>this._OpenPGPSignature.packets.findPacket(openpgp.enums.packet.signature).created;
    }

    get publicKeyAlgorithm() {

        return publicKeyAlgorithms.get(<number>this._OpenPGPSignature.packets.findPacket(openpgp.enums.packet.signature).publicKeyAlgorithm);
    }

    get hashAlgorithm() {

        return hashAlgorithms.get(<number>this._OpenPGPSignature.packets.findPacket(openpgp.enums.packet.signature).hashAlgorithm);
    }

    toUint8Array() {

        return <Uint8Array>this._OpenPGPSignature.packets.write();
    }

    toHex() {

        return uint8ArrayToHex(<Uint8Array>this._OpenPGPSignature.packets.findPacket(openpgp.enums.packet.signature).signature);
    }

    async verifyAsync(data: Uint8Array) {

        let verified = await openpgp.verify({ message: openpgp.message.fromBinary(data), signature: this._OpenPGPSignature, publicKeys: this.sendersPublicKey._OpenPGPKey });

        this.isVerified = verified.signatures[0].valid;
    }

    async ensureIsVerifiedAsync(data: Uint8Array) {

        let verification = await openpgp.verify({ message: openpgp.message.fromBinary(data), signature: this._OpenPGPSignature, publicKeys: this.sendersPublicKey._OpenPGPKey });

        if (!(this.isVerified = verification.signatures[0].valid))
            throw new SignatureVerificationFailedError();
    }

    static async fromUint8ArrayAsync(data: Uint8Array) {

        let result = new Signature();

        result._OpenPGPSignature = <openpgp.signature.Signature>(await openpgp.signature.read(data));

        return result;
    }
}

let publicKeyAlgorithms = new Map<number, string>();

publicKeyAlgorithms.set(1, "RSA (Encrypt or Sign)");
publicKeyAlgorithms.set(2, "RSA Encrypt-Onl");
publicKeyAlgorithms.set(3, "RSA Sign-Only");
publicKeyAlgorithms.set(16, "Elgamal (Encrypt-Only)");
publicKeyAlgorithms.set(17, "DSA (Digital Signature Algorithm)");
publicKeyAlgorithms.set(18, "ECDH public key algorithm");
publicKeyAlgorithms.set(19, "ECDSA public key algorithm");
publicKeyAlgorithms.set(22, "EdDSA");

let hashAlgorithms = new Map<number, string>();

hashAlgorithms.set(1, "MD5");
hashAlgorithms.set(2, "SHA1");
hashAlgorithms.set(3, "RIPEMD160");
hashAlgorithms.set(8, "SHA256");
hashAlgorithms.set(9, "SHA384");
hashAlgorithms.set(10, "SHA512");
hashAlgorithms.set(11, "SHA224");