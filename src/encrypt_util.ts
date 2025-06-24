import { cbc } from '@noble/ciphers/aes';

export class EncryptUtil {
    static blockSize = 16;

    static async encrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 创建 CBC 模式的 AES 加密器
        const aesCbc = cbc(aesKey, iv);
        // 执行加密
        return aesCbc.encrypt(data);
    }

    static async decrypt(aesKey: Uint8Array, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        // 创建 CBC 模式的 AES 解密器
        const aesCbc = cbc(aesKey, iv);
        // 执行解密
        return aesCbc.decrypt(data);
    }
}