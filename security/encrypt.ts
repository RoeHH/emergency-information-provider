import { deriveKeyFromPassword, toBase64 } from "./key-util.ts";

const iv = crypto.getRandomValues(new Uint8Array(12));

const key = await crypto.subtle.generateKey(
  {
    name: "AES-GCM",
    length: 256,
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt"],
);


const pdfFile = Deno.readFileSync(`./private/${Deno.args[0]}`);

const encryptedData = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: iv },
  key,
  pdfFile,
);

console.log("Encrypted PDF:", encryptedData, iv, key);

Deno.mkdirSync(`./public/assets/${Deno.args[0].split(".")[0]}`, { recursive: true });

Deno.writeFileSync(`./public/assets/${Deno.args[0].split(".")[0]}/encrypted.${Deno.args[0].split(".")[1]}`, new Uint8Array(encryptedData));

// Export key 
const wrapSalt = crypto.getRandomValues(new Uint8Array(16));
const wrapIv = crypto.getRandomValues(new Uint8Array(12));
const wrappingKey = await deriveKeyFromPassword(Deno.args[1], wrapSalt);
const rawKey = await crypto.subtle.exportKey("raw", key);

const wrappedKey = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: wrapIv },
  wrappingKey,
  rawKey,
);

const payload = {
  fileName: Deno.args[0],
  wrappedKey: toBase64(wrappedKey),
  wrapSalt: toBase64(wrapSalt),
  wrapIv: toBase64(wrapIv),
  iv: toBase64(iv),
};

console.log(JSON.stringify(payload, null, 2));

Deno.writeTextFileSync(`./public/assets/${Deno.args[0].split(".")[0]}/payload.json`, JSON.stringify(payload, null, 2));
