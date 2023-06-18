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

package crypto.rsa;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

public class DemoRsaOaep {
  private static final String RSA_OAEP_ALGO = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
  private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
      "SHA-512",
      "MGF1",
      MGF1ParameterSpec.SHA512,
      PSpecified.DEFAULT);

  public static KeyPair generateRsaKeys() throws Exception {
    // Generate RSA key 4096-bit
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(4096);
    return generator.generateKeyPair();
  }

  public static byte[] exportRsaPublicKey(final PublicKey publicKey) throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final X509EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
    final byte[] spkiPublicKey = publicKeySpec.getEncoded();
    return spkiPublicKey;
  }

  public static byte[] exportRsaPrivateKey(final PrivateKey privateKey) throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final PKCS8EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
    final byte[] pkcs8PrivateKey = privateKeySpec.getEncoded();
    return pkcs8PrivateKey;
  }

  public static PublicKey loadRsaPublicKey(final byte[] spkiPublicKey) throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(spkiPublicKey);
    final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    return publicKey;
  }

  public static PrivateKey loadRsaPrivateKey(final byte[] pkcs8PrivateKey) throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pkcs8PrivateKey);
    final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
    return privateKey;
  }

  public static byte[] encryptRsaOaep(final PublicKey publicKey, final byte[] message) throws Exception {
    final Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGO);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_PARAMS);
    final byte[] ciphertext = cipher.doFinal(message);
    return ciphertext;
  }

  public static byte[] decryptRsaOaep(final PrivateKey privateKey, final byte[] ciphertext) throws Exception {
    final Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGO);
    cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_PARAMS);
    final byte[] plaintext = cipher.doFinal(ciphertext);
    return plaintext;
  }

  public static byte[] signRsaSha256(final PrivateKey privateKey, final byte[] message) throws Exception {
    final Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(message);
    return signature.sign();
  }

  public static boolean verifySignRsaSha256(final PublicKey publicKey, final byte[] signature, final byte[] message) throws Exception {
    final Signature verifySignature = Signature.getInstance("SHA256withRSA");
    verifySignature.initVerify(publicKey);
    verifySignature.update(message);
    return verifySignature.verify(signature);
  }

  // Run With:
  // $ java DemoRsaOaep.java
  public static void main(final String[] args) throws Exception {
    final byte[] MESSAGE = "hello world".getBytes(StandardCharsets.UTF_8);

    final KeyPair pair = generateRsaKeys();
    final PublicKey publicKey = pair.getPublic();
    final PrivateKey privateKey = pair.getPrivate();

    final byte[] ciphertext = encryptRsaOaep(publicKey, MESSAGE);
    final byte[] plaintext = decryptRsaOaep(privateKey, ciphertext);
    if (!Arrays.equals(MESSAGE, plaintext)) {
      throw new IllegalArgumentException("Decryption failed");
    }

    final byte[] signature = signRsaSha256(privateKey, MESSAGE);
    final boolean verified = verifySignRsaSha256(publicKey, signature, MESSAGE);
    if (!verified) {
      throw new IllegalStateException("Verification not passed");
    }
  }
}
