
export interface NesignerInterface {
    getPublicKey(): Promise<string | null>;
    encrypt(pubkey: string, plaintext: string): Promise<string | null>;
    decrypt(pubkey: string, ciphertext: string): Promise<string | null>;
    nip44Encrypt(pubkey: string, plaintext: string): Promise<string | null>;
    nip44Decrypt(pubkey: string, ciphertext: string): Promise<string | null>;
    sign(eventId: string): Promise<string | null>;
    close(): Promise<void>;
}
