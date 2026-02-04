/// <reference lib="dom" />

// import { NesignerInterface } from './nesigner_interface';
import { HexUtil } from './hex_util';
import { EncryptUtil } from './encrypt_util';
import { getConversationKey, encrypt as nip44Encrypt, utf8Decoder, utf8Encoder } from './nip44';
import { schnorr } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { Md5 } from 'ts-md5';
import { bech32 } from '@scure/base';

export interface NesignerInterface {
    getPublicKey(): Promise<string | null>;
    encrypt(pubkey: string, plaintext: string): Promise<string | null>;
    decrypt(pubkey: string, ciphertext: string): Promise<string | null>;
    nip44Encrypt(pubkey: string, plaintext: string): Promise<string | null>;
    nip44Decrypt(pubkey: string, ciphertext: string): Promise<string | null>;
    sign(eventId: string): Promise<string | null>;
    close(): Promise<void>;

    updateKey(pinCode: string, key: string): Promise<number>;
    removeKey(pinCode: string): Promise<number>;
    ping(): Promise<number | null>;
    echo(pinCode: string, msgContent: string): Promise<string | null>;
}

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
    const filters = [{
        usbVendorId: 0x2323,
        usbProductId: 0x3434,
    }];

    const port = await navigator.serial.requestPort({ filters });
    await port.open({
        baudRate: 115200,
        dataBits: 8,
        stopBits: 1,
        parity: 'none',
        flowControl: 'none'
    });
    // console.log("Serial port opened:", port.getInfo());
    return port;
}

export async function createNesigner(port: SerialPort, pinCode: string): Promise<NesignerInterface> {
    class Nesigner implements NesignerInterface {
        private _pubkey?: string;
        private port: SerialPort;
        private aesKey: Uint8Array;
        private writeQueue: Array<() => Promise<void>> = [];
        private isWriting = false;

        private static readonly EMPTY_PUBKEY = "0000000000000000000000000000000000000000000000000000000000000000";

        constructor(port: SerialPort, pinCode: string) {
            this.port = port;
            this.aesKey = this.getAesKey(pinCode);
            this.startResponseReader();
        }

        private messageCallbacks: Map<string, (response: {
            type: number;
            result: number;
            pubkey: string;
            iv: Uint8Array | null;
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

            const iv = randomBytes(16);
            let data = new Uint8Array([
                ...iv
            ]);
            // console.log("iv:", iv);
            // console.log("data:", data);
            const response = await this.doRequest(
                this.aesKey,
                iv,
                MsgType.NOSTR_GET_PUBLIC_KEY,
                Nesigner.EMPTY_PUBKEY,
                data,
            );

            if (response && response.result === MsgResult.OK && response.data && response.iv) {
                var dectypedData = await EncryptUtil.decrypt(this.aesKey, response.data, response.iv);
                this._pubkey = HexUtil.bytesToHex(dectypedData);
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
            var response = await this.doRequest(this.aesKey, null, msgType, this._pubkey as string, data);
            if (response && response.result === MsgResult.OK && response.data && response.iv) {
                var dectypedData = await EncryptUtil.decrypt(this.aesKey, response.data, response.iv);
                return utf8Decoder.decode(dectypedData);
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
            var response = await this.doRequest(this.aesKey, null, MsgType.NOSTR_SIGN_EVENT, this._pubkey as string, HexUtil.hexToBytes(eventId));
            if (response && response.result === MsgResult.OK && response.data && response.iv) {
                var dectypedData = await EncryptUtil.decrypt(this.aesKey, response.data, response.iv);
                return HexUtil.bytesToHex(dectypedData);
            }
            return null;
        }

        async getTempPubkey(): Promise<string | null> {
            const response = await this.doRequest(
                null,
                null,
                MsgType.GET_TEMP_PUBKEY,
                Nesigner.EMPTY_PUBKEY,
                null,
            );

            if (response && response.result === MsgResult.OK && response.data) {
                return HexUtil.bytesToHex(response.data);
            }

            return null;
        }

        async updateKey(pinCode: string, key: string): Promise<number> {
            var aesKey = this.getAesKey(pinCode);

            // Check if the key is in nsec1 format (nostr bech32 encoded private key)
            let privateKeyBytes: Uint8Array;
            if (key.startsWith('nsec1')) {
                // Decode the nsec1 format key to get the hex representation
                try {
                    const result: any = bech32.decode(key as any, 1000); // 1000 is the max length limit
                    const { prefix, words } = result;
                    if (prefix !== 'nsec') {
                        console.error('Invalid prefix for nsec key:', prefix);
                        return MsgResult.FAIL;
                    }
                    const data = bech32.fromWords(words);
                    privateKeyBytes = new Uint8Array(data);
                } catch (error) {
                    console.error('Invalid nsec format key:', error);
                    return MsgResult.FAIL;
                }
            } else {
                // Assume it's already in hex format
                privateKeyBytes = HexUtil.hexToBytes(key);
            }

            var currentPubkey = this.getPublicKeyFromKey(privateKeyBytes);
            var tempPubkey = await this.getTempPubkey();
            if (!tempPubkey) {
                return MsgResult.FAIL;
            }

            var sourceData = HexUtil.bytesToHex(privateKeyBytes) + HexUtil.bytesToHex(aesKey);
            var sharedSecret = getConversationKey(privateKeyBytes, tempPubkey);
            var encryptedText = await nip44Encrypt(sourceData, sharedSecret);

            const response = await this.doRequest(
                null,
                null,
                MsgType.UPDATE_KEY,
                currentPubkey,
                utf8Encoder.encode(encryptedText),
            );
            if (response) {
                return response.result;
            }

            return MsgResult.FAIL;
        }

        async removeKey(pinCode: string): Promise<number> {
            var aesKey = this.getAesKey(pinCode);
            const iv = randomBytes(16);
            let data = new Uint8Array([
                ...iv
            ]);
            const response = await this.doRequest(
                aesKey,
                iv,
                MsgType.REMOVE_KEY,
                Nesigner.EMPTY_PUBKEY,
                data,
            );
            if (response) {
                return response.result;
            }

            return MsgResult.FAIL;
        }

        async ping(): Promise<number | null> {
            let data = new Uint8Array(0);
            var beginTime = new Date().getTime();
            const response = await this.doRequest(
                null,
                null,
                MsgType.PING,
                Nesigner.EMPTY_PUBKEY,
                data,
            );

            if (response && response.result == MsgResult.OK) {
                var endTime = new Date().getTime();
                return endTime - beginTime;
            }

            return null;
        }

        async echo(pinCode: string, msgContent: string): Promise<string | null> {
            var aesKey = this.getAesKey(pinCode);
            const response = await this.doRequest(
                aesKey,
                null,
                MsgType.ECHO,
                Nesigner.EMPTY_PUBKEY,
                utf8Encoder.encode(msgContent),
            );

            if (response && response.result == MsgResult.OK && response.data && response.iv) {
                var dectypedData = await EncryptUtil.decrypt(aesKey, response.data, response.iv);
                return utf8Decoder.decode(dectypedData);
            }

            return null;
        }

        async close(): Promise<void> {
            if (this.port.close) {
                await this.port.close();
            }
        }

        private async doRequest(
            aesKey: Uint8Array | null,
            iv: Uint8Array | null,
            messageType: number,
            pubkey: string,
            data: Uint8Array | null): Promise<{
                type: number;
                result: number;
                pubkey: string;
                iv: Uint8Array | null;
                data: Uint8Array | null;
            }> {
            // Generate random 16-byte messageId
            const messageId = randomBytes(16);

            return new Promise((resolve, reject) => {
                const messageIdStr = HexUtil.bytesToHex(messageId);
                this.messageCallbacks.set(messageIdStr, resolve);

                // console.log(`Sending message with ID: ${messageIdStr}, Type: ${messageType}, Pubkey: ${pubkey}`);

                this.sendMessage(aesKey, messageId, iv, messageType, pubkey, data)
                    .catch(err => {
                        this.messageCallbacks.delete(messageIdStr);
                        reject(err);
                    });
            });
        }

        private async sendMessage(
            aesKey: Uint8Array | null,
            messageId: Uint8Array,
            iv: Uint8Array | null,
            messageType: number,
            pubkey: string,
            data: Uint8Array | null
        ): Promise<void> {
            // Generate random 16-byte IV
            if (!iv) {
                iv = randomBytes(16);
            }

            const pubkeyBytes = HexUtil.hexToBytes(pubkey);
            var encryptedData = new Uint8Array(0);
            var dataLength = 0;
            if (data != null) {
                if (aesKey != null) {
                    const tempEncryptedData = await EncryptUtil.encrypt(aesKey, data, iv);
                    encryptedData = new Uint8Array(tempEncryptedData);
                } else {
                    encryptedData = new Uint8Array(data);
                }
            }
            dataLength = encryptedData.byteLength;

            // Prepare message structure
            const messageTypeBytes = new Uint8Array(2);
            messageTypeBytes[0] = messageType >> 8;
            messageTypeBytes[1] = messageType & 0xFF;

            const lengthBytes = new Uint8Array(4);
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
                lengthBytes,
                encryptedData,
                new Uint8Array(2), // Placeholder for CRC
            ];

            // Calculate total length and create final message
            const totalLength = 72 + dataLength; // 2 + 16 + 32 + 16 + 4 + dataLength + 2
            const finalMessage = new Uint8Array(totalLength);

            let offset = 0;
            for (const part of messageParts) {
                finalMessage.set(part, offset);
                offset += part.length;
            }

            // Calculate CRC16 (excluding CRC field itself)
            const crc = this.calculateCRC16(
                finalMessage,
                0,
                totalLength - 2,
            );
            finalMessage[totalLength - 2] = (crc >> 8) & 0xFF;
            finalMessage[totalLength - 1] = crc & 0xFF;

            // Send to serial port using queue
            return new Promise((resolve, reject) => {
                const writeTask = async () => {
                    // Send to serial port
                    const writer = this.port.writable?.getWriter();
                    if (!writer) {
                        reject(new Error('Serial port is not writable'));
                        return;
                    }

                    try {
                        await writer.write(finalMessage);
                        // console.log("write success");
                        resolve();
                    } catch (error) {
                        reject(error);
                    } finally {
                        writer.releaseLock();
                        this.processWriteQueue();
                    }
                };

                this.writeQueue.push(writeTask);
                this.processWriteQueue();
            });
        }

        private async processWriteQueue(): Promise<void> {
            if (this.isWriting || this.writeQueue.length === 0) {
                return;
            }

            // console.log("processWriteQueue", this.writeQueue.length);

            this.isWriting = true;
            const task = this.writeQueue.shift();

            if (task) {
                try {
                    await task();
                } catch (error) {
                    console.error('Write task failed:', error);
                } finally {
                    this.isWriting = false;
                    this.processWriteQueue();
                }
            } else {
                this.isWriting = false;
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
                const headerLength = 72;
                const headerBuffer = new Uint8Array(headerLength);
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
                const dataLength = (headerBuffer[68] << 24) | (headerBuffer[69] << 16) |
                    (headerBuffer[70] << 8) | headerBuffer[71];

                // console.log('result:', result);
                // console.log('read dataLength:', dataLength);

                // Read encrypted data
                const encryptedDataAndCrcLength = dataLength + 2;
                const encryptedDataAndCrc = new Uint8Array(encryptedDataAndCrcLength);
                let dataOffset = 0;

                // Use existing data first if available
                if (existingData) {
                    const copyLength = Math.min(existingData.length, encryptedDataAndCrcLength);
                    encryptedDataAndCrc.set(existingData.slice(0, copyLength));
                    dataOffset = copyLength;

                    // Save remaining data for next message
                    existingData = existingData.length > copyLength ?
                        existingData.slice(copyLength) :
                        null;
                }

                // Read remaining encrypted data
                while (dataOffset < encryptedDataAndCrcLength) {
                    const { value, done } = await reader.read();
                    if (done) {
                        throw new Error('Serial port closed while reading data');
                    }

                    const remaining = encryptedDataAndCrcLength - dataOffset;
                    if (value.length <= remaining) {
                        encryptedDataAndCrc.set(value, dataOffset);
                        dataOffset += value.length;
                    } else {
                        encryptedDataAndCrc.set(value.slice(0, remaining), dataOffset);
                        existingData = value.slice(remaining);
                        dataOffset += remaining;
                        break;
                    }
                }

                const encryptedData = encryptedDataAndCrc.slice(0, dataLength);
                const crc = (encryptedDataAndCrc[encryptedDataAndCrcLength - 2] << 8) | encryptedDataAndCrc[encryptedDataAndCrcLength - 1];
                if (dataLength > 0) {
                    // Verify CRC
                    const fullCrcLength = headerLength + dataLength;
                    const crcData = new Uint8Array(fullCrcLength);
                    crcData.set(headerBuffer, 0);
                    crcData.set(encryptedData, headerLength);
                    const calculatedCrc = this.calculateCRC16(crcData, 0, fullCrcLength);
                    if (calculatedCrc !== crc) {
                        throw new Error('CRC verification failed');
                    }
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
                        iv,
                        data: encryptedData,
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

        private calculateCRC16(data: Uint8Array, offset: number, length: number): number {
            let crc = 0xFFFF;
            for (let i = offset; i < length; i++) {
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

        private getAesKey(pinCode: string): Uint8Array {
            return HexUtil.hexToBytes(Md5.hashStr(pinCode));
        }

        private getPublicKeyFromKey(key: Uint8Array): string {
            return HexUtil.bytesToHex(schnorr.getPublicKey(key))
        }
    }

    return new Nesigner(port, pinCode);
}