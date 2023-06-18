/*
 * Copyright (c) 2023 Matteo Bertozzi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

async function generateRsaKeys(): Promise<CryptoKeyPair> {
  // Generate RSA key 4096-bit
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-512",
    },
    true,
    ["encrypt", "decrypt"],
  );
  return keyPair;
}

async function exportPublicKey(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const spkiPublicKey = await crypto.subtle.exportKey("spki", publicKey);
  return spkiPublicKey;
}

async function exportPrivateKey(privateKey: CryptoKey): Promise<ArrayBuffer> {
  const pkcs8PrivateKey = await crypto.subtle.exportKey("pkcs8", privateKey);
  return pkcs8PrivateKey;
}

async function loadRsaOaepPublicKey(spkiPublicKey: BufferSource): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    spkiPublicKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-512"
    },
    true,
    ["encrypt"]
  );
}

async function loadRsaOaepPrivateKey(pkcs8PrivateKey: BufferSource): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "pkcs8",
    pkcs8PrivateKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-512",
    },
    true,
    ["decrypt"]
  );
}

async function rsaOaepEncrypt(publicKey: CryptoKey, message: BufferSource): Promise<ArrayBuffer> {
  return await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    message
  );
}

async function rsaOaepDecrypt(privateKey: CryptoKey, message: BufferSource): Promise<ArrayBuffer> {
  return await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    message
  );
}

async function loadRsaPrivateKeyForSigning(pkcs8PrivateKey: BufferSource): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "pkcs8",
    pkcs8PrivateKey,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["sign"]
  );
}

async function loadRsaPublicKeyForVerifyingSignature(spkiPublicKey: BufferSource): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    spkiPublicKey,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"]
  );
}

async function rsaSign(privateKey: CryptoKey, message: BufferSource): Promise<ArrayBuffer> {
  return await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    message,
  );
}

async function rsaVerifySign(publicKey: CryptoKey, signature: BufferSource, message: BufferSource): Promise<boolean> {
  return await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    message
  );
}

async function demoMain() {
  const MESSAGE = new TextEncoder().encode('hello world');

  const rsaKeys = await generateRsaKeys();
  const spkiPublicKey = await exportPublicKey(rsaKeys.publicKey);
  const pkcs8PrivateKey = await exportPrivateKey(rsaKeys.privateKey);
  const encPublicKey = await loadRsaOaepPublicKey(spkiPublicKey);
  const verifyPublicKey = await loadRsaPublicKeyForVerifyingSignature(spkiPublicKey);
  const decPrivateKey = await loadRsaOaepPrivateKey(pkcs8PrivateKey);
  const signPrivateKey = await loadRsaPrivateKeyForSigning(pkcs8PrivateKey);

  const ciphertext = await rsaOaepEncrypt(encPublicKey, MESSAGE)
  const plaintext = await rsaOaepDecrypt(decPrivateKey, ciphertext);
  console.log(new TextDecoder().decode(plaintext));

  const signature = await rsaSign(signPrivateKey, MESSAGE);
  const verified = await rsaVerifySign(verifyPublicKey, signature, MESSAGE);
  console.log(verified);
}

// run with:
//  $ deno run ./DemoRsaOaep.ts
//  $ bun run ./DemoRsaOaep.ts
await demoMain();
