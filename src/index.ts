/// <reference lib="dom" />
declare const CryptoJS: any;

import { NesignerInterface } from './nesigner_interface';
// import { MD5 } from 'crypto-js';
import { HexUtil } from './hex_util';
import { EncryptUtil } from './encrypt_util';

export enum MsgType {
    NOSTR_GET_PUBLIC_KEY = 1,
    NOSTR_SIGN_EVENT = 2,
    NOSTR_GET_RELAYS = 3,
    NOSTR_NIP04_ENCRYPT = 4,
    NOSTR_NIP04_DECRYPT = 5,
    NOSTR_NIP44_ENCRYPT = 6,
    NOSTR_NIP44_DECRYPT = 7,

    PING = 0,
    ECHO = 11,
    UPDATE_KEY = 12,
    REMOVE_KEY = 13,
    GET_TEMP_PUBKEY = 14,
}

export enum MsgResult {
    FAIL = 0,
    OK = 1,

    KEY_NOT_FOUND = 101,
    CONTENT_NOT_ALLOW_EMPTY = 102,
    CONTENT_ILLEGAL = 103,
}

export async function getSerialPort(): Promise<SerialPort> {
    const port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200 });
    return port;
}

export async function createNesigner(port: SerialPort, pinCode: string): Promise<NesignerInterface> {
    class Nesigner implements NesignerInterface {
        private _pubkey?: string;
        private port: SerialPort;
        private aesKey: Uint8Array;

        private static readonly EMPTY_PUBKEY = "0000000000000000000000000000000000000000000000000000000000000000";

        constructor(port: SerialPort, pinCode: string) {
            this.port = port;
            this.aesKey = HexUtil.hexToBytes(CryptoJS.MD5(pinCode).toString());
            this.startResponseReader();
        }

        private messageCallbacks: Map<string, (response: {
            type: number;
            result: number;
            pubkey: string;
            data: Uint8Array | null;
        }) => void> = new Map();

        private startResponseReader() {
            // console.log('Starting response reader...');
            this.readResponse(null).catch(err => {
                console.error('Error in response reader:', err);
            });
        }

        async getPublicKey(): Promise<string | null> {
            if (this._pubkey) {
                return this._pubkey;
            }

            const iv = crypto.getRandomValues(new Uint8Array(16));
            let data = new Uint8Array([
                ...iv
            ]);
            // console.log("iv:", iv);
            // console.log("data:", data);
            const response = await this.doRequest(
                iv,
                MsgType.NOSTR_GET_PUBLIC_KEY,
                Nesigner.EMPTY_PUBKEY,
                data,
            );

            if (response && response.result === MsgResult.OK && response.data) {
                this._pubkey = HexUtil.bytesToHex(response.data);
                return this._pubkey;
            } else if (response && response.result === MsgResult.KEY_NOT_FOUND) {
                // Key not found, retry
                return null;
            }

            return null;
        }

        async _encryptOrDecrypt(msgType: number, pubkey: string, targetText: string): Promise<string | null> {
            const data = new Uint8Array([
                ...HexUtil.hexToBytes(pubkey),         // 转换16进制字符串为字节数组
                ...new TextEncoder().encode(targetText) // UTF-8编码文本
            ]);
            var response = await this.doRequest(null, msgType, this._pubkey as string, data);
            if (response && response.result === MsgResult.OK && response.data) {
                return new TextDecoder().decode(response.data);
            }

            return null;
        }

        async encrypt(pubkey: string, plaintext: string): Promise<string | null> {
            return this._encryptOrDecrypt(MsgType.NOSTR_NIP04_ENCRYPT, pubkey, plaintext);
        }

        async decrypt(pubkey: string, ciphertext: string): Promise<string | null> {
            return this._encryptOrDecrypt(MsgType.NOSTR_NIP04_DECRYPT, pubkey, ciphertext);
        }

        async nip44Encrypt(pubkey: string, plaintext: string): Promise<string | null> {
            return this._encryptOrDecrypt(MsgType.NOSTR_NIP44_ENCRYPT, pubkey, plaintext);
        }

        async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string | null> {
            return this._encryptOrDecrypt(MsgType.NOSTR_NIP44_DECRYPT, pubkey, ciphertext);
        }

        async sign(eventId: string): Promise<string | null> {
            var response = await this.doRequest(null, MsgType.NOSTR_SIGN_EVENT, this._pubkey as string, HexUtil.hexToBytes(eventId));
            if (response && response.result === MsgResult.OK && response.data) {
                return HexUtil.bytesToHex(response.data);
            }
            return null;
        }

        async close(): Promise<void> {
            if (this.port.close) {
                await this.port.close();
            }
        }

        private async doRequest(
            iv: Uint8Array | null,
            messageType: number,
            pubkey: string,
            data: Uint8Array): Promise<{
                type: number;
                result: number;
                pubkey: string;
                data: Uint8Array | null;
            }> {
            // Generate random 16-byte messageId
            const messageId = crypto.getRandomValues(new Uint8Array(16));

            return new Promise((resolve, reject) => {
                const messageIdStr = HexUtil.bytesToHex(messageId);
                this.messageCallbacks.set(messageIdStr, resolve);

                // console.log(`Sending message with ID: ${messageIdStr}, Type: ${messageType}, Pubkey: ${pubkey}`);

                this.sendMessage(messageId, iv, messageType, pubkey, data)
                    .catch(err => {
                        this.messageCallbacks.delete(messageIdStr);
                        reject(err);
                    });
            });
        }

        private async sendMessage(
            messageId: Uint8Array,
            iv: Uint8Array | null,
            messageType: number,
            pubkey: string,
            data: Uint8Array
        ): Promise<void> {
            // Generate random 16-byte IV
            if (!iv) {
                iv = crypto.getRandomValues(new Uint8Array(16));
            }

            const pubkeyBytes = HexUtil.hexToBytes(pubkey);
            const encryptedData = await EncryptUtil.encrypt(this.aesKey, data, iv);

            // Prepare message structure
            const messageTypeBytes = new Uint8Array(2);
            messageTypeBytes[0] = messageType >> 8;
            messageTypeBytes[1] = messageType & 0xFF;

            const lengthBytes = new Uint8Array(4);
            const dataLength = encryptedData.byteLength;
            lengthBytes[0] = (dataLength >> 24) & 0xFF;
            lengthBytes[1] = (dataLength >> 16) & 0xFF;
            lengthBytes[2] = (dataLength >> 8) & 0xFF;
            lengthBytes[3] = dataLength & 0xFF;

            // Combine all parts except CRC
            const messageParts = [
                messageTypeBytes,
                messageId,
                pubkeyBytes,
                iv,
                new Uint8Array(2), // Placeholder for CRC
                lengthBytes,
                encryptedData,
            ];

            // Calculate total length and create final message
            const totalLength = messageParts.reduce((sum, arr) => sum + arr.length, 0);
            const finalMessage = new Uint8Array(totalLength);

            let offset = 0;
            for (const part of messageParts) {
                finalMessage.set(part, offset);
                offset += part.length;
            }

            // Calculate CRC16 (excluding CRC field itself)
            const crc = this.calculateCRC16(
                encryptedData
            );
            finalMessage[66] = (crc >> 8) & 0xFF;
            finalMessage[67] = crc & 0xFF;

            // Send to serial port
            const writer = this.port.writable?.getWriter();
            if (!writer) {
                throw new Error('Serial port is not writable');
            }

            try {
                await writer.write(finalMessage);
            } finally {
                writer.releaseLock();
            }
        }

        private async readResponse(existingData: Uint8Array | null): Promise<void> {
            const reader = this.port.readable?.getReader();
            if (!reader) {
                console.error('Serial port is not readable');
                throw new Error('Serial port is not readable');
            }

            try {
                // Header buffer and offset
                const headerBuffer = new Uint8Array(74);
                let headerOffset = 0;

                // If we have existing data from previous read, use it first
                if (existingData) {
                    const copyLength = Math.min(existingData.length, headerBuffer.length);
                    headerBuffer.set(existingData.slice(0, copyLength));
                    headerOffset = copyLength;

                    // Save remaining data if we got more than header size
                    existingData = existingData.length > copyLength ?
                        existingData.slice(copyLength) :
                        null;
                }

                // Read until we have complete header
                while (headerOffset < headerBuffer.length) {
                    // console.log(`Reading header: ${headerOffset}/${headerBuffer.length}`);
                    const { value, done } = await reader.read();
                    if (done) {
                        throw new Error('Serial port closed while reading');
                    }

                    // console.log(`Read ${value.length} bytes from serial port`);

                    const remaining = headerBuffer.length - headerOffset;
                    if (value.length <= remaining) {
                        headerBuffer.set(value, headerOffset);
                        headerOffset += value.length;
                    } else {
                        headerBuffer.set(value.slice(0, remaining), headerOffset);
                        existingData = value.slice(remaining);
                        headerOffset += remaining;
                    }
                }

                // Parse header
                const type = (headerBuffer[0] << 8) | headerBuffer[1];
                const messageId = headerBuffer.slice(2, 18);
                const result = (headerBuffer[18] << 8) | headerBuffer[19];
                const pubkeyBytes = headerBuffer.slice(20, 52);
                const iv = headerBuffer.slice(52, 68);
                const crc = (headerBuffer[68] << 8) | headerBuffer[69];
                const dataLength = (headerBuffer[70] << 24) | (headerBuffer[71] << 16) |
                    (headerBuffer[72] << 8) | headerBuffer[73];

                // console.log('result:', result);
                // console.log('read dataLength:', dataLength);

                // Read encrypted data
                const encryptedData = new Uint8Array(dataLength);
                let dataOffset = 0;

                // Use existing data first if available
                if (existingData) {
                    const copyLength = Math.min(existingData.length, dataLength);
                    encryptedData.set(existingData.slice(0, copyLength));
                    dataOffset = copyLength;

                    // Save remaining data for next message
                    existingData = existingData.length > copyLength ?
                        existingData.slice(copyLength) :
                        null;
                }

                // Read remaining encrypted data
                while (dataOffset < dataLength) {
                    const { value, done } = await reader.read();
                    if (done) {
                        throw new Error('Serial port closed while reading data');
                    }

                    const remaining = dataLength - dataOffset;
                    if (value.length <= remaining) {
                        encryptedData.set(value, dataOffset);
                        dataOffset += value.length;
                    } else {
                        encryptedData.set(value.slice(0, remaining), dataOffset);
                        existingData = value.slice(remaining);
                        dataOffset += remaining;
                        break;
                    }
                }

                let decryptedData: Uint8Array | null = null;
                if (dataLength > 0) {
                    // Verify CRC
                    const crcData = encryptedData;
                    const calculatedCrc = this.calculateCRC16(crcData);
                    if (calculatedCrc !== crc) {
                        throw new Error('CRC verification failed');
                    }

                    decryptedData = await EncryptUtil.decrypt(this.aesKey, encryptedData, iv);
                }

                // Convert pubkey bytes to hex string
                const pubkey = HexUtil.bytesToHex(pubkeyBytes);

                // Find and execute callback
                const messageIdStr = HexUtil.bytesToHex(messageId);
                const callback = this.messageCallbacks.get(messageIdStr);

                if (callback) {
                    this.messageCallbacks.delete(messageIdStr);
                    callback({
                        type,
                        result,
                        pubkey,
                        data: decryptedData ? decryptedData : null
                    });
                }

                // Continue reading next message
                reader.releaseLock();
                this.readResponse(existingData).catch(err => {
                    console.error('Error in response reader:', err);
                });

            } catch (error) {
                reader.releaseLock();
                throw error;
            }
        }

        private calculateCRC16(data: Uint8Array): number {
            let crc = 0xFFFF;
            for (let i = 0; i < data.length; i++) {
                crc ^= data[i] << 8;
                for (let j = 0; j < 8; j++) {
                    // 修改这里的逻辑以匹配 C++ 实现
                    crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
                    // 保持 16 位
                    crc &= 0xFFFF;
                }
            }
            return crc;
        }
    }

    return new Nesigner(port, pinCode);
}