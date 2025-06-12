
export interface NesignerInterface {
    getPublicKey(): Promise<string>;
    encrypt(pubkey: string, plaintext: string): Promise<string>;
    decrypt(pubkey: string, ciphertext: string): Promise<string>;
    nip44Encrypt(pubkey: string, plaintext: string): Promise<string>;
    nip44Decrypt(pubkey: string, ciphertext: string): Promise<string>;
    signEvent(event: any): Promise<string>;
    close(): Promise<void>;
}
