export async function deriveKeyFromPassword(password: string, salt: BufferSource) {
  const enc = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 300_000,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
}


export function fromBase64(b64: string) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function toBase64(buf: ArrayLike<number> | ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
