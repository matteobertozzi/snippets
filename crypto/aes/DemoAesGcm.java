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

package crypto.aes;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DemoAesGcm {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private static SecretKey generateAesKey() throws Exception {
    // Generate AES-256 key
    final KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(256);
    return generator.generateKey();
  }

  public static byte[] exportAesKey(final SecretKey key) {
    // Export Raw Key
    return key.getEncoded();
  }

  public static SecretKey loadAesKey(final byte[] rawKey) throws Exception {
    // Convert to SecretKey object
    return new SecretKeySpec(rawKey, "AES");
  }

  public static byte[] aesGcmEncrypt(final SecretKey key, final byte[] message) throws Exception {
    // Generate 96bit Initialization Vector
    final byte[] iv = new byte[12];
    SECURE_RANDOM.nextBytes(iv);

    // Init AES-GCM
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      // add the IV
      baos.write(iv);
      // encrypt the 'message'
      baos.write(cipher.doFinal(message));
      // Get the full cipherText: IV + Encrypted-Message + Auth-Tag
      return baos.toByteArray();
    }
  }

  public static byte[] aesGcmDecrypt(final SecretKey key, final byte[] cipherText) throws Exception {
    // Init AES-GCM, IV is in the first 12bytes of the ciphertext
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final GCMParameterSpec gcmSpec = new GCMParameterSpec(128, cipherText, 0, 12);
    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
    // Decrypt the message (exclude the IV)
    return cipher.doFinal(cipherText, 12, cipherText.length - 12);
  }

  // Run With:
  // $ java DemoAesGcm.java
  public static void main(final String[] args) throws Exception {
    final byte[] MESSAGE = "hello world".getBytes(StandardCharsets.UTF_8);

    final SecretKey aesKey = generateAesKey();
    final byte[] ciphertext = aesGcmEncrypt(aesKey, MESSAGE);
    final byte[] plaintext = aesGcmDecrypt(aesKey, ciphertext);
    System.out.println("AES-KEY: " + Base64.getEncoder().encodeToString(exportAesKey(aesKey)));
    System.out.println("AES-KEY: " + Base64.getEncoder().encodeToString(ciphertext));
    System.out.println("AES-KEY: " + new String(plaintext));
  }
}