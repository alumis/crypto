// import { ObservableWithError, Observable } from "@alumis/observables/src/Observable";
// import { Signature } from "./Signature";
// import { encode, decode } from "@msgpack/msgpack";
// import { KeyPair } from "./KeyPair";
// import { Key } from "./Key";

// export class ObservableSecureMessage<T> extends ObservableWithError<T> {

//     static createSecureMessage<T>(value?: T) {

//         var result = new ObservableSecureMessage<T>();

//         result.wrappedValue = value;

//         return result;
//     }

//     signature = Observable.create<Signature>();

//     private _plaintext: Uint8Array;

//     async signAsync(sendersKeyPair: KeyPair) {

//         if (!this._plaintext)
//             this._plaintext = encode(this.wrappedValue);

//         let signature = new Signature();
//         let message = openpgp.message.fromBinary(this._plaintext);

//         signature._OpenPGPSignature = await openpgp.signature.readArmored((await openpgp.sign({ message: message, privateKeys: sendersKeyPair.privateKey._OpenPGPKey, detached: true })).signature);
//         signature.sendersPublicKey = sendersKeyPair.publicKey;
//         signature.isVerified = true;

//         this.signature.value = signature;
//     }

//     async ensureAuthenticityAsync(sendersPublicKey: Key) {

//         if (sendersPublicKey) {

//             let signature = this.signature.value;

//             if (signature) {

//                 if (signature.isVerified && signature.sendersPublicKey === sendersPublicKey)
//                     return;

//                 signature.isVerified = false;
//                 signature.sendersPublicKey = sendersPublicKey;

//                 this.signature.invalidate();

//                 try {

//                     await signature.ensureIsVerifiedAsync(this._plaintext);
//                 }

//                 catch (e) {

//                     this.error.value = e;
//                     throw e;
//                 }

//                 finally {

//                     this.signature.invalidate();
//                 }
//             }

//             else console.warn("Unable to ensure authenticity of possibly signed message because there is no signature to verify against");
//         }

//         else console.warn("Unable to ensure authenticity of possibly signed message because there is no public key to verify against");
//     }

//     async attemptToEnsureAuthenticityAsync(sendersPublicKey: Key) {

//         try {

//             await this.ensureAuthenticityAsync(sendersPublicKey);
//         }

//         catch (e) {

//             this.error.value = e;
//         }
//     }

//     async toAsymmetricallyEncryptedUint8ArrayAsync(recipientsPublicKey: Key) {

//         if (!this._plaintext)
//             this._plaintext = encode(this.value);

//         let signature = this.signature.value;
//         let plaintextAndSignature = encode([this._plaintext, signature ? signature.toUint8Array() : null]);
//         let ciphertext = <Uint8Array>(await openpgp.encrypt({ message: openpgp.message.fromBinary(plaintextAndSignature), publicKeys: recipientsPublicKey._OpenPGPKey, armor: false })).message.packets.write();

//         return ciphertext;
//     }

//     async toSymmetricallyEncryptedUint8ArrayAsync(password: string) {

//         if (!this._plaintext)
//             this._plaintext = encode(this.value);

//         let signature = this.signature.value;
//         let plaintextAndSignature = encode([this._plaintext, signature ? signature.toUint8Array() : null]);
//         let ciphertext = <Uint8Array>(await openpgp.encrypt({ message: openpgp.message.fromBinary(plaintextAndSignature), passwords: password, armor: false })).message.packets.write();

//         return ciphertext;
//     }

//     async setFromAsymmetricallyEncryptedUint8ArrayAsync(ciphertext: Uint8Array, recipientsPrivateKey: Key) {

//         let toInvalidate: Observable<any>[] = [];

//         if (this.wrappedValue) {

//             this.wrappedValue = undefined;
//             toInvalidate.push(this);
//         }

//         if (this.signature) {

//             this.signature.wrappedValue = undefined;
//             toInvalidate.push(this.signature);
//         }

//         this.error.value = undefined;

//         for (let o of toInvalidate)
//             o.invalidate();

//         toInvalidate = [];

//         try {

//             let message = await openpgp.message.read(ciphertext);
//             let plaintextAndSignature = decode(<Uint8Array>(await openpgp.decrypt({ message: message, privateKeys: recipientsPrivateKey._OpenPGPKey, format: "binary" })).data) as Array<any>;

//             this.wrappedValue = decode(this._plaintext = plaintextAndSignature[0]) as T;
//             toInvalidate.push(this);

//             if (plaintextAndSignature[1]) {

//                 this.signature.wrappedValue = await Signature.fromUint8ArrayAsync(plaintextAndSignature[1]);
//                 toInvalidate.push(this.signature);
//             }
//         }

//         catch (e) {

//             this.error.value = e;
//             throw e;
//         }

//         finally {

//             for (let o of toInvalidate)
//                 o.invalidate();
//         }
//     }

//     async attemptToSetFromAsymmetricallyEncryptedUint8ArrayAsync(ciphertext: Uint8Array, recipientsPrivateKey: Key) {

//         try {

//             this.setFromAsymmetricallyEncryptedUint8ArrayAsync(ciphertext, recipientsPrivateKey);
//         }

//         catch (e) {

//             this.error.value = e;
//         }
//     }

//     async setFromSymmetricallyEncryptedUint8ArrayAsync(ciphertext: Uint8Array, password: string) {

//         let toInvalidate: Observable<any>[] = [];

//         if (this.wrappedValue) {

//             this.wrappedValue = undefined;
//             toInvalidate.push(this);
//         }

//         if (this.signature) {

//             this.signature.wrappedValue = undefined;
//             toInvalidate.push(this.signature);
//         }

//         this.error.value = undefined;

//         for (let o of toInvalidate)
//             o.invalidate();

//         toInvalidate = [];

//         try {

//             let message = await openpgp.message.read(ciphertext);
//             let plaintextAndSignature = decode(<Uint8Array>(await openpgp.decrypt({ message: message, passwords: password, format: "binary" })).data) as Array<any>;

//             this.wrappedValue = decode(this._plaintext = plaintextAndSignature[0]) as T;
//             toInvalidate.push(this);

//             if (plaintextAndSignature[1]) {

//                 this.signature.wrappedValue = await Signature.fromUint8ArrayAsync(plaintextAndSignature[1]);
//                 toInvalidate.push(this.signature);
//             }
//         }

//         catch (e) {

//             this.error.value = e;
//             throw e;
//         }

//         finally {

//             for (let o of toInvalidate)
//                 o.invalidate();
//         }
//     }

//     async attemptToSetFromSymmetricallyEncryptedUint8ArrayAsync(ciphertext: Uint8Array, password: string) {

//         try {

//             this.setFromSymmetricallyEncryptedUint8ArrayAsync(ciphertext, password);
//         }

//         catch (e) {

//             this.error.value = e;
//         }
//     }

//     dispose() {

//         delete this.wrappedValue;

//         this.error.dispose();
//         delete this.error;

//         this.signature.dispose();
//         delete this.signature;

//         let node = this._prioritizedHead;

//         if (node) {

//             for (node = node.next; node !== this._prioritizedTail;) {

//                 let currentNode = node;

//                 node = node.next;
//                 currentNode.recycle();
//             }

//             this._prioritizedHead.recycle();
//             delete this._prioritizedHead;;

//             this._prioritizedTail.recycle();
//             delete this._prioritizedTail;;
//         }

//         for (node = this._head.next; node !== this._tail;) {

//             let currentNode = node;

//             node = node.next;
//             currentNode.recycle();
//         }

//         this._head.recycle();
//         delete this._head;

//         this._tail.recycle();
//         delete this._tail;
//     }
// }