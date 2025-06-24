import { cbc } from '@noble/ciphers/aes';

export class EncryptUtil {
    static blockSize = 16;

    /**
     * 使用 PKCS7 算法对数据进行填充
     * @param data 需要填充的数据
     * @param blockSize 块大小
     * @returns 填充后的数据
     */
    private static pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
        const paddingLength = blockSize - (data.length % blockSize);
        const padding = new Uint8Array(paddingLength).fill(paddingLength);
        const paddedData = new Uint8Array(data.length + paddingLength);
        paddedData.set(data);
        paddedData.set(padding, data.length);
        return paddedData;
    }

    /**
     * 使用 PKCS7 算法去除数据的填充
     * @param data 需要去除填充的数据
     * @param blockSize 块大小
     * @returns 去除填充后的数据
     */
    private static pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
        const paddingLength = data[data.length - 1];
        if (paddingLength > blockSize || paddingLength === 0) {
            throw new Error('Invalid PKCS7 padding');
        }
        for (let i = 0; i < paddingLength; i++) {
            if (data[data.length - 1 - i] !== paddingLength) {
                throw new Error('Invalid PKCS7 padding');
            }
        }
        return data.subarray(0, data.length - paddingLength);
    }

    static async encrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 使用 PKCS7 填充数据
        const paddedData = this.pkcs7Pad(data, this.blockSize);
        // 创建 CBC 模式的 AES 加密器
        const aesCbc = cbc(aesKey, iv);
        // 执行加密
        return aesCbc.encrypt(paddedData);
    }

    static async decrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 创建 CBC 模式的 AES 解密器
        const aesCbc = cbc(aesKey, iv);
        // 执行解密
        const decryptedData = aesCbc.decrypt(data);
        // 使用 PKCS7 去除填充
        return this.pkcs7Unpad(decryptedData, this.blockSize);
    }
}