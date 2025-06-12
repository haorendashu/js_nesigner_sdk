export class HexUtil {
    /**
     * Convert a hex string to Uint8Array
     * @param hex The hex string to convert
     * @returns Uint8Array containing the bytes
     */
    static hexToBytes(hex: string): Uint8Array {
        if (hex.length % 2 !== 0) {
            throw new Error('Hex string must have an even number of characters');
        }

        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    /**
     * Convert Uint8Array to hex string
     * @param bytes The bytes to convert
     * @returns Hex string representation
     */
    static bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}