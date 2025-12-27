import { deriveKeyFromPassword, fromBase64 } from "./key-util.ts";

const payload = JSON.parse(Deno.readTextFileSync(`./public/assets/${Deno.args[0].split(".")[0]}/payload.json`));

const password = Deno.args[1];

const wrappingKey = await deriveKeyFromPassword(
  password,
  fromBase64(payload.wrapSalt),
);

const rawKey = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: fromBase64(payload.wrapIv) },
  wrappingKey,
  fromBase64(payload.wrappedKey),
);

const importedKey = await crypto.subtle.importKey(
  "raw",
  rawKey,
  { name: "AES-GCM" },
  true,
  ["encrypt", "decrypt"],
);

const encryptedData = Deno.readFileSync(`./public/assets/${Deno.args[0].split(".")[0]}/encrypted.${Deno.args[0].split(".")[1]}`).buffer;

const decryptedData = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: fromBase64(payload.iv) },
  importedKey,
  encryptedData
);

Deno.mkdirSync(`./decrypted`, { recursive: true });

Deno.writeFileSync(`./decrypted/${Deno.args[0]}.pdf`, new Uint8Array(decryptedData));
