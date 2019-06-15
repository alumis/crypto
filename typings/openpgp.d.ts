declare namespace openpgp {
    class AsyncProxy {
        constructor(args: any[]);
        delegate(e: any, t: any): any;
        getID(): any;
        seedRandom(e: any, t: any, args: any[]): any;
        terminate(): void;
    }
    class ECDHSymmetricKey {
        constructor(e: any);
        read(e: any): any;
        write(): any;
    }
    class HKP {
        constructor(t: any);
        lookup(e: any): any;
        upload(e: any): any;
    }
    class KDFParams {
        constructor(e: any);
        read(e: any): any;
        write(): any;
    }
    class Keyid {
        constructor();
        equals(e: any, args: any[]): any;
        isNull(): any;
        isWildcard(): any;
        read(e: any): void;
        toHex(): any;
        write(): any;
    }
    class Keyring {
        constructor(e: any);
        clear(): void;
        getAllKeys(): any;
        getKeysForId(e: any, t: any): any;
        removeKeysForId(e: any): any;
        store(): void;
    }
    class MPI {
        constructor(e: any);
        bitLength(): any;
        byteLength(): any;
        fromBN(e: any): void;
        fromString(e: any, args: any[]): void;
        fromUint8Array(e: any, args: any[]): void;
        read(e: any, args: any[]): any;
        toBN(): any;
        toString(): any;
        toUint8Array(e: any, t: any): any;
        write(e: any, t: any): any;
    }
    class OID {
        constructor(e: any);
        getName(): any;
        read(e: any): any;
        toHex(): any;
        write(): any;
    }
    class S2K {
        constructor();
        get_count(): any;
        produce_key(e: any, t: any): any;
        read(e: any): any;
        write(): any;
    }
    const config: {
        aead_chunk_size_byte: number;
        aead_mode: number;
        aead_protect: boolean;
        aead_protect_version: number;
        checksum_required: boolean;
        commentstring: string;
        compression: number;
        debug: boolean;
        deflate_level: number;
        encryption_cipher: number;
        ignore_mdc_error: boolean;
        integrity_protect: boolean;
        keyserver: string;
        node_store: string;
        password_collision_check: boolean;
        prefer_hash_algorithm: number;
        revocations_expire: boolean;
        rsa_blinding: boolean;
        s2k_iteration_count_byte: number;
        show_comment: boolean;
        show_version: boolean;
        tolerant: boolean;
        use_native: boolean;
        versionstring: string;
        zero_copy: boolean;
    };
    function decrypt(e: { message: message.Message; privateKeys?: key.Key | key.Key[]; passwords?: string | string[]; sessionKeys?: { data: Uint8Array; algorithm: string; } | { data: Uint8Array; algorithm: string; }[]; publicKeys?: key.Key | key.Key[]; format?: string; signature?: signature.Signature; date?: Date; }): Promise<{ data: Uint8Array | string, filename: string, signatures: [{ keyid: string, valid: boolean }] }>;
    function decryptKey(e: any): any;
    function decryptSessionKeys(e: any): any;
    function destroyWorker(): void;
    function encrypt(e: any): any;
    function encryptSessionKey(e: any): any;
    function generateKey(e: any): Promise<{ key: key.Key, privateKeyArmored: string, publicKeyArmored: string }>;
    function getWorker(): any;
    function initWorker(args: { path?: string; n?: number; workers?: Array<any>; }): any;
    function reformatKey(e: any): any;
    function sign(e: any): { data?: string; message?: message.Message; signature?: string; };
    function verify(e: { message: cleartext.CleartextMessage; publicKeys: key.Key[] | key.Key; signature?: signature.Signature; date?: Date; }): Promise<{ data: string; signatures: { keyid: string; valid: boolean }[]; }>;
    namespace ECDHSymmetricKey {
        function fromClone(e: any): any;
    }
    namespace KDFParams {
        function fromClone(e: any): any;
    }
    namespace Keyid {
        function fromClone(e: any): any;
        function fromId(e: any): any;
        function mapToHex(e: any): any;
        function wildcard(): any;
    }
    namespace Keyring {
        class localstore {
            constructor(t: any);
            loadPrivate(): any;
            loadPublic(): any;
            storePrivate(e: any): void;
            storePublic(e: any): void;
        }
    }
    namespace MPI {
        function fromClone(e: any): any;
    }
    namespace OID {
        function fromClone(e: any): any;
    }
    namespace S2K {
        function fromClone(e: any): any;
    }
    namespace armor {
        function decode(e: any): any;
        function encode(e: any, t: any, r?: any, a?: any): any;
    }
    namespace cleartext {
        class CleartextMessage {
            constructor(e: any, t: any);
            armor(): any;
            getSigningKeyIds(): any;
            getText(): any;
            sign(e: any, args: any[]): any;
            signDetached(e: any, args: any[]): any;
            verify(e: any, args: any[]): any;
            verifyDetached(e: any, t: any, args: any[]): any;
            signature: signature.Signature;
            text: string;
        }
        function readArmored(e: any): Promise<CleartextMessage>;
        function fromText(text: string): CleartextMessage;
    }
    namespace crypto {
        const pkcs1: {
            eme: {
                decode: any;
                encode: any;
            };
            emsa: {
                encode: any;
            };
        };
        const publicKey: {
            dsa: {
                sign: any;
                verify: any;
            };
            elgamal: {
                decrypt: any;
                encrypt: any;
            };
            elliptic: {
                Curve: any;
                ecdh: {
                    decrypt: any;
                    encrypt: any;
                };
                ecdsa: {
                    sign: any;
                    verify: any;
                };
                eddsa: {
                    sign: any;
                    verify: any;
                };
                generate: any;
                getPreferredHashAlgo: any;
            };
            rsa: {
                decrypt: any;
                encrypt: any;
                generate: any;
                prime: {
                    divisionTest: any;
                    fermat: any;
                    isProbablePrime: any;
                    millerRabin: any;
                    randomProbablePrime: any;
                };
                sign: any;
                verify: any;
            };
        };
        function constructParams(e: any, t: any): any;
        function eax(e: any, t: any, args: any[]): any;
        function experimental_gcm(e: any, t: any, args: any[]): any;
        function gcm(e: any, t: any, args: any[]): any;
        function generateParams(e: any, t: any, r: any): any;
        function generateSessionKey(e: any): any;
        function getEncSessionKeyParamTypes(e: any): any;
        function getPrefixRandom(e: any): any;
        function getPrivKeyParamTypes(e: any): any;
        function getPubKeyParamTypes(e: any): any;
        function ocb(e: any, t: any, args: any[]): any;
        function publicKeyDecrypt(t: any, r: any, n: any, i: any, args: any[]): any;
        function publicKeyEncrypt(t: any, r: any, n: any, i: any, args: any[]): any;
        namespace aes_kw {
            function unwrap(e: any, t: any): any;
            function wrap(e: any, t: any): any;
        }
        namespace cfb {
            function decrypt(e: any, t: any, r: any, n: any): any;
            function encrypt(e: any, t: any, r: any, n: any, i: any): any;
            function mdc(e: any, t: any, r: any): any;
            function normalDecrypt(e: any, t: any, r: any, n: any): any;
            function normalEncrypt(e: any, t: any, r: any, n: any): any;
        }
        namespace cipher {
            class aes128 {
                constructor(e: any);
            }
            class aes192 {
                constructor(e: any);
            }
            class aes256 {
                constructor(e: any);
            }
            class blowfish {
                constructor(e: any);
            }
            class cast5 {
                constructor(e: any);
            }
            class tripledes {
                constructor(e: any);
            }
            class twofish {
                constructor(e: any);
            }
            function des(e: any): any;
            function idea(): void;
            namespace aes128 {
                const blockSize: number;
                const keySize: number;
            }
            namespace aes192 {
                const blockSize: number;
                const keySize: number;
            }
            namespace aes256 {
                const blockSize: number;
                const keySize: number;
            }
            namespace blowfish {
                const blockSize: number;
                const keySize: number;
            }
            namespace cast5 {
                const blockSize: number;
                const keySize: number;
            }
            namespace tripledes {
                const blockSize: number;
                const keySize: number;
            }
            namespace twofish {
                const blockSize: number;
                const keySize: number;
            }
        }
        namespace hash {
            function digest(e: any, t: any): any;
            function getHashByteLength(e: any): any;
            function md5(e: any): any;
            function ripemd(t: any): Uint8Array;
            function sha1(e: any): any;
            function sha224(t: any): any;
            function sha256(e: any): any;
            function sha384(t: any): any;
            function sha512(t: any): any;
        }
        namespace pkcs5 {
            function decode(e: any): any;
            function encode(e: any): any;
        }
        namespace random {
            function getRandomBN(t: any, r: any, args: any[]): any;
            function getRandomBytes(t: any, args?: any[]): any;
            namespace randomBuffer {
                const buffer: any;
                const callback: any;
                const size: any;
                function get(e: any, args: any[]): any;
                function init(e: any, t: any): void;
                function set(e: any): void;
            }
        }
        namespace signature {
            function sign(t: any, r: any, n: any, i: any, args: any[]): any;
            function verify(t: any, r: any, n: any, i: any, a: any, args: any[]): any;
        }
    }
    //namespace default {
    //    function decrypt(e: any, args: any[]): any;
    //    function decryptKey(e: any): any;
    //    function decryptSessionKeys(e: any): any;
    //    function destroyWorker(): void;
    //    function encrypt(e: any): any;
    //    function encryptKey(e: any): any;
    //    function encryptSessionKey(e: any): any;
    //    function generateKey(e: any): any;
    //    function getWorker(): any;
    //    function initWorker(args: any[]): any;
    //    function reformatKey(e: any): any;
    //    function sign(e: any): any;
    //    function verify(e: any): any;
    //}
    namespace enums {
        const aead: {
            eax: number;
            experimental_gcm: number;
            ocb: number;
        };
        const armor: {
            message: number;
            multipart_last: number;
            multipart_section: number;
            private_key: number;
            public_key: number;
            signature: number;
            signed: number;
        };
        const compression: {
            bzip2: number;
            uncompressed: number;
            zip: number;
            zlib: number;
        };
        const curve: {
            "1.2.840.10045.3.1.7": string;
            "1.3.132.0.10": string;
            "1.3.132.0.34": string;
            "1.3.132.0.35": string;
            "1.3.36.3.3.2.8.1.1.11": string;
            "1.3.36.3.3.2.8.1.1.13": string;
            "1.3.36.3.3.2.8.1.1.7": string;
            "1.3.6.1.4.1.11591.15.1": string;
            "1.3.6.1.4.1.3029.1.5.1": string;
            "2A8648CE3D030107": string;
            "2B060104019755010501": string;
            "2B06010401DA470F01": string;
            "2B2403030208010107": string;
            "2B240303020801010B": string;
            "2B240303020801010D": string;
            "2B8104000A": string;
            "2B81040022": string;
            "2B81040023": string;
            "2a8648ce3d030107": string;
            "2b060104019755010501": string;
            "2b06010401da470f01": string;
            "2b2403030208010107": string;
            "2b240303020801010b": string;
            "2b240303020801010d": string;
            "2b8104000a": string;
            "2b81040022": string;
            "2b81040023": string;
            Curve25519: string;
            ED25519: string;
            Ed25519: string;
            "P-256": string;
            "P-384": string;
            "P-521": string;
            X25519: string;
            brainpoolP256r1: string;
            brainpoolP384r1: string;
            brainpoolP512r1: string;
            curve25519: string;
            cv25519: string;
            ed25519: string;
            p256: string;
            p384: string;
            p521: string;
            prime256v1: string;
            secp256k1: string;
            secp256r1: string;
            secp384r1: string;
            secp521r1: string;
        };
        const features: {
            aead: number;
            modification_detection: number;
            v5_keys: number;
        };
        const hash: {
            md5: number;
            ripemd: number;
            sha1: number;
            sha224: number;
            sha256: number;
            sha384: number;
            sha512: number;
        };
        const keyFlags: {
            authentication: number;
            certify_keys: number;
            encrypt_communication: number;
            encrypt_storage: number;
            shared_private_key: number;
            sign_data: number;
            split_private_key: number;
        };
        const keyStatus: {
            expired: number;
            invalid: number;
            no_self_cert: number;
            revoked: number;
            valid: number;
        };
        const literal: {
            binary: number;
            mime: number;
            text: number;
            utf8: number;
        };
        const packet: {
            compressed: number;
            literal: number;
            marker: number;
            modificationDetectionCode: number;
            onePassSignature: number;
            publicKey: number;
            publicKeyEncryptedSessionKey: number;
            publicSubkey: number;
            secretKey: number;
            secretSubkey: number;
            signature: number;
            symEncryptedAEADProtected: number;
            symEncryptedIntegrityProtected: number;
            symEncryptedSessionKey: number;
            symmetricallyEncrypted: number;
            trust: number;
            userAttribute: number;
            userid: number;
        };
        const publicKey: {
            aedh: number;
            aedsa: number;
            dsa: number;
            ecdh: number;
            ecdsa: number;
            eddsa: number;
            elgamal: number;
            rsa_encrypt: number;
            rsa_encrypt_sign: number;
            rsa_sign: number;
        };
        const s2k: {
            gnu: number;
            iterated: number;
            salted: number;
            simple: number;
        };
        const signature: {
            binary: number;
            cert_casual: number;
            cert_generic: number;
            cert_persona: number;
            cert_positive: number;
            cert_revocation: number;
            key: number;
            key_binding: number;
            key_revocation: number;
            standalone: number;
            subkey_binding: number;
            subkey_revocation: number;
            text: number;
            third_party: number;
            timestamp: number;
        };
        const signatureSubpacket: {
            embedded_signature: number;
            exportable_certification: number;
            features: number;
            issuer: number;
            issuer_fingerprint: number;
            key_expiration_time: number;
            key_flags: number;
            key_server_preferences: number;
            notation_data: number;
            placeholder_backwards_compatibility: number;
            policy_uri: number;
            preferred_aead_algorithms: number;
            preferred_compression_algorithms: number;
            preferred_hash_algorithms: number;
            preferred_key_server: number;
            preferred_symmetric_algorithms: number;
            primary_user_id: number;
            reason_for_revocation: number;
            regular_expression: number;
            revocable: number;
            revocation_key: number;
            signature_creation_time: number;
            signature_expiration_time: number;
            signature_target: number;
            signers_user_id: number;
            trust_signature: number;
        };
        const symmetric: {
            aes128: number;
            aes192: number;
            aes256: number;
            blowfish: number;
            cast5: number;
            idea: number;
            plaintext: number;
            tripledes: number;
            twofish: number;
        };
        const webHash: {
            "SHA-1": number;
            "SHA-256": number;
            "SHA-384": number;
            "SHA-512": number;
        };
        function read(e: any, t: any): any;
        function write(e: any, t: any): any;
    }
    namespace key {
        class Key {
            constructor(e: any);
            armor(): string;
            decrypt(e: any, args?: any[]): Promise<void>;
            encrypt(e: any, args?: any[]): Promise<any>;
            getEncryptionKeyPacket(e: any, args: any[]): any;
            getExpirationTime(args: any[]): any;
            getKeyIds(): any;
            getKeyPackets(args: any[]): any;
            getPrimaryUser(args: any[]): any;
            getSigningKeyPacket(args: any[]): any;
            getSubkeyPackets(args: any[]): any;
            getUserIds(): any;
            isPrivate(): any;
            isPublic(): any;
            isRevoked(e: any, t: any, args: any[]): any;
            packetlist2structure(e: any): void;
            revoke(): void;
            signAllUsers(e: any, args: any[]): any;
            signPrimaryUser(e: any, args: any[]): any;
            toPacketlist(): any;
            toPublic(): any;
            update(e: any, args: any[]): any;
            verifyAllUsers(e: any, args: any[]): any;
            verifyPrimaryKey(args: any[]): any;
            verifyPrimaryUser(e: any, args: any[]): any;
        }
        function generate(e: any, args: any[]): any;
        function getPreferredAlgo(e: any, t: any, r: any, args: any[]): any;
        function getPreferredHashAlgo(e: any, t: any, args: any[]): any;
        function isAeadSupported(e: any, t: any, args: any[]): any;
        function read(e: any): Promise<Uint8Array>;
        function readArmored(e: any): Promise<{ keys: key.Key[], err: Array<Error> | null }>;
        function reformat(e: any, args: any[]): any;
    }
    namespace message {
        class Message {
            constructor(e: any);
            appendSignature(e: any): void;
            armor(): any;
            compress(e: any): any;
            decrypt(e: any, t: any, r: any, args: any[]): any;
            decryptSessionKeys(e: any, t: any, args: any[]): any;
            encrypt(e: any, t: any, r: any, args: any[]): any;
            getEncryptionKeyIds(): any;
            getFilename(): any;
            getLiteralData(): any;
            getSigningKeyIds(): any;
            getText(): any;
            sign(args: any[]): any;
            signDetached(args: any[]): any;
            unwrapCompressed(): any;
            verify(e: any, args: any[]): any;
            verifyDetached(e: any, t: any, args: any[]): any;
        }
        function createSignaturePackets(e: any, t: any, args: any[]): any;
        function createVerificationObjects(e: any, t: any, r: any, args: any[]): any;
        function encryptSessionKey(e: any, t: any, r: any, i: any, a: any, args: any[]): any;
        function fromBinary(binary: Uint8Array): any;
        function fromText(text: string): any;
        function read(e: Uint8Array): Promise<Message>;
        function readArmored(e: any): any;
    }
    namespace packet {
        class Compressed {
            constructor();
            compress(): void;
            decompress(): void;
            read(e: any): void;
            write(): any;
        }
        class List {
            constructor();
            concat(e: any): any;
            every(e: any): any;
            filter(e: any): any;
            filterByTag(args: any[]): any;
            findPacket(e: any): any;
            forEach(e: any): void;
            indexOfTag(args: any[]): any;
            map(e: any): any;
            pop(): any;
            push(e: any): void;
            read(e: any): void;
            slice(e: any, t: any): any;
            some(e: any, args: any[]): any;
            write(): any;
        }
        class Literal {
            constructor(args: any[]);
            getBytes(): any;
            getFilename(): any;
            getText(): any;
            read(e: any): void;
            setBytes(e: any, t: any): void;
            setFilename(e: any): void;
            setText(e: any, args: any[]): void;
            write(): any;
        }
        class Marker {
            constructor();
            read(e: any): any;
        }
        class OnePassSignature {
            constructor();
            postCloneTypeFix(): void;
            read(e: any): any;
            write(): any;
        }
        class PublicKey {
            constructor(args: any[]);
            getAlgorithmInfo(): any;
            getFingerprint(): any;
            getFingerprintBytes(): any;
            getKeyId(): any;
            postCloneTypeFix(): void;
            read(e: any): any;
            readPublicKey(e: any): any;
            write(): any;
            writeOld(): any;
            writePublicKey(): any;
        }
        class PublicKeyEncryptedSessionKey {
            constructor();
            decrypt(e: any, args: any[]): any;
            encrypt(e: any, args: any[]): any;
            postCloneTypeFix(): void;
            read(e: any): void;
            write(): any;
        }
        class PublicSubkey {
            constructor();
        }
        class SecretKey {
            constructor(args: any[]);
            clearPrivateParams(): void;
            decrypt(e: any, args: any[]): any;
            encrypt(e: any, args: any[]): any;
            generate(e: any, t: any): any;
            postCloneTypeFix(): void;
            read(e: any): void;
            write(): any;
        }
        class SecretSubkey {
            constructor(args: any[]);
        }
        class Signature {
            constructor(args: any[]);
            calculateTrailer(): any;
            getExpirationTime(): any;
            isExpired(args: any[]): any;
            postCloneTypeFix(): void;
            read(e: any): any;
            read_sub_packet(e: any): void;
            sign(e: any, t: any, args: any[]): any;
            toSign(e: any, t: any): any;
            verify(e: any, t: any, args: any[]): any;
            write(): any;
            write_all_sub_packets(): any;
        }
        class SymEncryptedAEADProtected {
            constructor();
            crypt(e: any, t: any, r: any, n: any, args: any[]): any;
            decrypt(e: any, t: any, args: any[]): any;
            encrypt(e: any, t: any, args: any[]): any;
            read(e: any): void;
            write(): any;
        }
        class SymEncryptedIntegrityProtected {
            constructor();
            decrypt(e: any, t: any, args: any[]): any;
            encrypt(e: any, t: any, args: any[]): any;
            read(e: any): void;
            write(): any;
        }
        class SymEncryptedSessionKey {
            constructor();
            decrypt(e: any, args: any[]): any;
            encrypt(e: any, args: any[]): any;
            postCloneTypeFix(): void;
            read(e: any): void;
            write(): any;
        }
        class SymmetricallyEncrypted {
            constructor();
            decrypt(e: any, t: any, args: any[]): any;
            encrypt(e: any, t: any, args: any[]): any;
            read(e: any): void;
            write(): any;
        }
        class Trust {
            constructor();
            read(): void;
        }
        class UserAttribute {
            constructor();
            equals(e: any): any;
            read(e: any): void;
            write(): any;
        }
        class Userid {
            constructor();
            read(e: any): void;
            write(): any;
        }
        function fromStructuredClone(e: any): any;
        function newPacketFromTag(e: any): any;
        namespace List {
            function fromStructuredClone(e: any): any;
        }
        namespace clone {
            function clonePackets(e: any): any;
            function parseClonedPackets(e: any): any;
        }
    }
    namespace signature {
        class Signature {
            constructor(e: any);
            armor(): any;
            packets: packet.List;
        }
        function read(e: any): any;
        function readArmored(e: any): Promise<Signature>;
    }
    namespace util {
        function Uint8Array_to_MPI(e: any): any;
        function Uint8Array_to_b64(e: Uint8Array, t?: boolean): string;
        function Uint8Array_to_hex(e: any): any;
        function Uint8Array_to_str(e: Uint8Array): string;
        function b64_to_Uint8Array(e: string): Uint8Array;
        function calc_checksum(e: any): any;
        function canonicalizeEOL(e: any): any;
        function collectBuffers(e: any, t: any): void;
        function concatUint8Array(e: any): any;
        function copyUint8Array(e: any): any;
        function decode_utf8(e: any): any;
        function detectNode(): any;
        function double(e: any): any;
        function encode_utf8(e: any): any;
        function equalsUint8Array(e: any, t: any): any;
        function getLeftNBits(e: any, t: any): any;
        function getNodeBuffer(): any;
        function getNodeCrypto(): any;
        function getNodeZlib(): any;
        function getTransferables(e: any): any;
        function getWebCrypto(): any;
        function getWebCryptoAll(): any;
        function hex_to_Uint8Array(e: any): any;
        function hex_to_str(e: any): any;
        function isArray(e: any): any;
        function isEmailAddress(e: any): any;
        function isString(e: any): any;
        function isUint8Array(e: any): any;
        function isUserId(e: any): any;
        function nativeEOL(e: any): any;
        function nbits(e: any): any;
        function normalizeDate(args: any[]): any;
        function print_debug(e: any): void;
        function print_debug_error(e: any): void;
        function print_debug_hexarray_dump(e: any, t: any): void;
        function print_debug_hexstr_dump(e: any, t: any): void;
        function readDate(e: any): any;
        function readNumber(e: any): any;
        function removeTrailingSpaces(e: any): any;
        function shiftRight(e: any, t: any): any;
        function str_to_Uint8Array(e: any): any;
        function str_to_hex(e: string): string;
        function writeDate(e: any): any;
        function writeNumber(e: any, t: any): any;
    }
}
