/*
 * Copyright (c) 2025 Matteo Bertozzi
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

import { Database } from "bun:sqlite";

import * as fido2 from '@simplewebauthn/server';

export class AuthStorage {
  private db?: Database;

  open() {
    this.db = new Database('auth.db');
    this.db.run(`CREATE TABLE IF NOT EXISTS user_passkey (
      userId BINARY,
      keyId BINARY,
      publicKey BINARY NOT NULL,
      counter BIGINT NOT NULL,
      transports TEXT,
      PRIMARY KEY (userId, keyId)
    )`);
  }

  close() {
    this.db?.close();
  }

  add(userId: Uint8Array, credential: fido2.WebAuthnCredential) {
    this.db?.run('INSERT INTO user_passkey (userId, keyId, publicKey, counter, transports) VALUES (?,?,?,?,?)', [
      userId, Buffer.from(credential.id, 'base64url'),
      credential.publicKey, credential.counter,
      credential.transports ? JSON.stringify(credential.transports) : null,
    ]);
  }

  get(userId: Uint8Array, keyId: string): { userId: Uint8Array, credential: fido2.WebAuthnCredential } | null {
    const row = this.db?.query('SELECT * FROM user_passkey WHERE userId = ? AND keyId = ?').as(UserPassKey)
      .get(userId, Buffer.from(keyId, 'base64url'));

    return row ? {
      userId: row.userId,
      credential: {
        id: Buffer.from(row.keyId).toString('base64url'),
        publicKey: row.publicKey,
        counter: row.counter,
        transports: row.transports ? JSON.parse(row.transports) : null,
      }
    } : null;
  }
}

class UserPassKey {
  userId!: Uint8Array;
  keyId!: Uint8Array;
  publicKey!: Uint8Array;
  counter!: number;
  transports!: string | null;
}