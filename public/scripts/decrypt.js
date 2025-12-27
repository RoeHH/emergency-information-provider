async function decryptPdfAndDownload(password, pdfName) {

  const { iv, key } = await getIvAndKey(pdfName);
  const encryptedPdfData = await fetch(`./assets/${pdfName}/encrypted.pdf`).then(res => res.arrayBuffer());

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encryptedPdfData
  );

  const blob = new Blob([decryptedData], { type: 'application/pdf' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${pdfName}.pdf`;
  link.click();
}

async function decryptJson(password, jsonName) {
  const { iv, key } = await getIvAndKey(jsonName);

  const encryptedJsonData = await fetch(`./assets/${jsonName}/encrypted.json`).then(res => res.arrayBuffer());

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encryptedJsonData
  );

  return JSON.parse(new TextDecoder().decode(decryptedData));
}

async function getIvAndKey(assetName) {

  const payload = await fetch(`./assets/${assetName}/payload.json`).then(res => res.json());
  
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

  return { iv: fromBase64(payload.iv), key: importedKey };
}


async function deriveKeyFromPassword(password, salt) {
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


function fromBase64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}