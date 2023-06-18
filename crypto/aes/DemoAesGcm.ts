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

async function generateAesGcmKey() {
  // Generate AES-256 Key
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportAesKey(key: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.exportKey("raw", key);
}

async function loadAesGcmKey(rawKey: BufferSource) {
  // Convert to CryptoKey object
  return await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function aesGcmEncrypt(key: CryptoKey, message: ArrayBuffer): Promise<Uint8Array> {
  // Generate 96bit Initialization Vector
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  // Encrypt the 'message'
  const aesData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    message,
  );

  // Compose the ciphertext: IV + Encrypted-Message + Auth-Tag
  const ciphertext = new Uint8Array(iv.byteLength + aesData.byteLength);
  ciphertext.set(iv, 0);
  ciphertext.set(new Uint8Array(aesData), 12);
  return ciphertext;
}

async function aesGcmDecrypt(key: CryptoKey, ciphertext: Uint8Array): Promise<Uint8Array> {
  // IV is in the first 12bytes of the ciphertext
  const iv = ciphertext.slice(0, 12);
  // AES encrypted data + GCM auth-tag
  const aesData = ciphertext.slice(12);

  // decrypt data
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    aesData
  );
  return new Uint8Array(plaintext);
}


async function demoMain() {
  const MESSAGE = new TextEncoder().encode('hello world');

  const aesKey = await generateAesGcmKey();
  const ciphertext = await aesGcmEncrypt(aesKey, MESSAGE)
  const plaintext = await aesGcmDecrypt(aesKey, ciphertext)

  console.log('AES key', aesKey);
  console.log('Ciphertext', ciphertext);
  console.log('Plaintext', plaintext);
}

// run with:
//  $ deno run ./DemoAesGcm.ts
//  $ bun run ./DemoAesGcm.ts
await demoMain();
