/// <reference lib="dom" />

import { NesignerInterface } from './nesigner_interface';
import { MD5 } from 'crypto-js';
import { HexUtil } from './hex_util';

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
        private pubkey?: string;
        private port: SerialPort;
        private aesKey: string;

        private static readonly EMPTY_PUBKEY = "0000000000000000000000000000000000000000000000000000000000000000";

        constructor(port: SerialPort, pinCode: string) {
            this.port = port;
            this.aesKey = MD5(pinCode).toString();
            this.startResponseReader();
        }

        private messageCallbacks: Map<string, (response: {
            type: number;
            result: number;
            pubkey: string;
            data: Uint8Array;
        }) => void> = new Map();

        private startResponseReader() {
            this.readResponse(null).catch(err => {
                console.error('Error in response reader:', err);
            });
        }

        async getPublicKey(): Promise<string | null> {
            if (this.pubkey) {
                return this.pubkey;
            }

            const iv = crypto.getRandomValues(new Uint8Array(16));
            let data = new Uint8Array([
                ...iv
            ]);
            const response = await this.doRequest(
                iv,
                MsgType.NOSTR_GET_PUBLIC_KEY,
                Nesigner.EMPTY_PUBKEY,
                data,
            );

            if (response && response.result === MsgResult.OK) {
                this.pubkey = HexUtil.bytesToHex(response.data);
                return this.pubkey;
            } else if (response && response.result === MsgResult.KEY_NOT_FOUND) {
                // Key not found, retry
                return null;
            } else {
                throw new Error('Failed to get public key');
            }

            return null;
        }

        async encrypt(pubkey: string, plaintext: string): Promise<string | null> {
            // TODO: Implement encryption
            throw new Error('Not implemented');
        }

        async decrypt(pubkey: string, ciphertext: string): Promise<string | null> {
            // TODO: Implement decryption
            throw new Error('Not implemented');
        }

        async nip44Encrypt(pubkey: string, plaintext: string): Promise<string | null> {
            // TODO: Implement NIP-44 encryption
            throw new Error('Not implemented');
        }

        async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string | null> {
            // TODO: Implement NIP-44 decryption
            throw new Error('Not implemented');
        }

        async signEvent(event: any): Promise<string | null> {
            // TODO: Implement event signing
            throw new Error('Not implemented');
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
                data: Uint8Array;
            }> {
            // Generate random 16-byte messageId
            const messageId = crypto.getRandomValues(new Uint8Array(16));

            return new Promise((resolve, reject) => {
                const messageIdStr = HexUtil.bytesToHex(messageId);
                this.messageCallbacks.set(messageIdStr, resolve);

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

            // Convert pubkey from hex to bytes (32 bytes)
            const pubkeyBytes = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                pubkeyBytes[i] = parseInt(pubkey.substr(i * 2, 2), 16);
            }

            // Encrypt data using AES-256-CBC
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(this.aesKey),
                { name: 'AES-CBC' },
                false,
                ['encrypt']
            );
            const encryptedData = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv },
                cryptoKey,
                data
            );

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
                new Uint8Array(encryptedData)
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
                new Uint8Array([
                    ...finalMessage.slice(0, 66),  // Before CRC
                    ...finalMessage.slice(68)      // After CRC
                ])
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
                    const { value, done } = await reader.read();
                    if (done) {
                        throw new Error('Serial port closed while reading');
                    }

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

                // Verify CRC
                const crcData = new Uint8Array([
                    ...headerBuffer.slice(0, 68),
                    ...headerBuffer.slice(70, 74),
                    ...encryptedData
                ]);
                const calculatedCrc = this.calculateCRC16(crcData);
                if (calculatedCrc !== crc) {
                    throw new Error('CRC verification failed');
                }

                // Decrypt data
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(this.aesKey),
                    { name: 'AES-CBC' },
                    false,
                    ['decrypt']
                );
                const decryptedData = await crypto.subtle.decrypt(
                    { name: 'AES-CBC', iv },
                    cryptoKey,
                    encryptedData
                );

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
                        data: new Uint8Array(decryptedData)
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
                    if (crc & 0x8000) {
                        crc = (crc << 1) ^ 0x1021;
                    } else {
                        crc = crc << 1;
                    }
                    crc &= 0xFFFF;
                }
            }
            return crc;
        }
    }

    return new Nesigner(port, pinCode);
}