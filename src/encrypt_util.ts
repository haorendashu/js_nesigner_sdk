
export class EncryptUtil {

    static blockSize = 16;

    private static arrayToWordArray(arr: Uint8Array): CryptoJS.lib.WordArray {
        // 直接将 Uint8Array 转换为 WordArray
        return CryptoJS.lib.WordArray.create(arr);
    }

    private static wordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray): Uint8Array {
        // 转换 WordArray 为 Uint8Array
        const words = wordArray.words;
        const sigBytes = wordArray.sigBytes;
        const u8 = new Uint8Array(sigBytes);
        let offset = 0;
        for (let i = 0; i < words.length && offset < sigBytes; i++) {
            const word = words[i];
            u8[offset++] = (word >>> 24) & 0xff;
            if (offset < sigBytes) u8[offset++] = (word >>> 16) & 0xff;
            if (offset < sigBytes) u8[offset++] = (word >>> 8) & 0xff;
            if (offset < sigBytes) u8[offset++] = word & 0xff;
        }
        return u8;
    }

    static async encrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 直接使用 Uint8Array 创建 WordArray
        const keyWordArray = this.arrayToWordArray(aesKey);
        const ivWordArray = this.arrayToWordArray(iv);
        const dataWordArray = this.arrayToWordArray(data);

        // 执行加密
        const encrypted = CryptoJS.AES.encrypt(dataWordArray, keyWordArray, {
            iv: ivWordArray,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });

        // 返回加密后的数据
        return this.wordArrayToUint8Array(encrypted.ciphertext);
    }

    static async decrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 直接使用 Uint8Array 创建 WordArray
        const keyWordArray = this.arrayToWordArray(aesKey);
        const ivWordArray = this.arrayToWordArray(iv);
        const encryptedWordArray = this.arrayToWordArray(data);

        // 创建 CipherParams
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: encryptedWordArray
        });

        // 执行解密
        const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWordArray, {
            iv: ivWordArray,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });

        // 返回解密后的数据
        return this.wordArrayToUint8Array(decrypted);
    }
}