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

import { AllowPublic, MessageError, UriMapping, UriMethod, UriPrefix, Verify, type MessageRequest } from "@tashkewey/core";

import * as fido2 from '@simplewebauthn/server';
import type { AuthStorage } from "./auth-storage";

@UriPrefix('/webauthn/v0')
export class WebAuthnHandler {
  readonly origin = 'http://localhost:57028';
  readonly rpName = 'Demo WebAuthn';
  readonly rpId = 'localhost';

  private readonly pendingRegistrations = new Map<string, PendingUserData>();
  private readonly pendingAuthentications = new Map<string, PendingOperationData>();
  private readonly authStorage: AuthStorage;

  constructor(authStorage: AuthStorage) {
    this.authStorage = authStorage;
  }

  @AllowPublic()
  @UriMapping({ uri: '/client' })
  client(): Response {
    return new Response(Bun.file('./webauthn-client.html'));
  }

  private newUserId(): Uint8Array {
    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);
    userId[6] &= 0x0f;  // clear version
    userId[6] |= 0x40;  // set to version 4
    userId[8] &= 0x3f;  // clear variant
    userId[8] |= 0x80;  // set to IETF variant
    return userId;
  }

  @AllowPublic()
  @UriMapping({ uri: '/register/options', method: UriMethod.POST })
  async registerOptions(message: MessageRequest<RegistrationInitialData>) {
    const sessionId = crypto.randomUUID();
    const userId = this.newUserId();

    const options = await fido2.generateRegistrationOptions({
      rpID: this.rpId,
      rpName: this.rpName,
      userID: userId,
      userName: message.body.username,
      userDisplayName: message.body.username,
      authenticatorSelection: { userVerification: "required" },
      timeout: 60_000,
    });
    console.log(sessionId, 'OPTIONS', options);

    this.pendingRegistrations.set(sessionId, {
      timestamp: Date.now() * options.timeout!,
      challenge: options.challenge,
      userId,
    });
    return { sessionId, options };
  }

  @AllowPublic()
  @UriMapping({ uri: '/register', method: UriMethod.POST })
  async register(request: MessageRequest<RegistrationRequest>) {
    console.log('REGISTER REQ', request.body);
    const userId = Verify.expectNotEmpty('id', request.body.registration.id);
    const userData = this.pendingRegistrations.get(request.body.sessionId);
    if (!userData) {
      throw MessageError.badRequest('INVALID_SESSION', 'invalid user session');
    }

    this.pendingRegistrations.delete(userId);
    const verification = await fido2.verifyRegistrationResponse({
      response: request.body.registration,
      expectedRPID: this.rpId,
      expectedOrigin: this.origin,
      expectedChallenge: userData.challenge,
      requireUserVerification: true,
    });
    console.log('VERIFY', verification);

    if (!verification.verified) {
      throw MessageError.badRequest('NOT_VERIFIED', 'user not verified');
    }

    if (!verification.registrationInfo) {
      throw MessageError.badRequest('MISSING_REGISTRATION_INFO', 'missing registration info');
    }

    console.log('REGISTER USER', userId, verification.registrationInfo.credential);
    this.authStorage.add(userData.userId, verification.registrationInfo.credential);
    return verification;
  }


  @AllowPublic()
  @UriMapping({ uri: '/authenticate/options', method: UriMethod.POST })
  async authenticateOptions() {
    const sessionId = crypto.randomUUID();

    const options = await fido2.generateAuthenticationOptions({
      rpID: this.rpId,
      userVerification: 'required',
      timeout: 60_000,
    });
    console.log(sessionId, 'AUTH OPTIONS', options);

    this.pendingAuthentications.set(sessionId, {
      timestamp: Date.now() + options.timeout!,
      challenge: options.challenge,
    });
    return { sessionId, options };
  }

  @AllowPublic()
  @UriMapping({ uri: '/authenticate', method: UriMethod.POST })
  async authenticate(request: MessageRequest<AuthenticationRequest>) {
    console.log('AUTH REQ', request.body);

    const opData = this.pendingAuthentications.get(request.body.sessionId);
    if (!opData) {
      throw MessageError.badRequest('INVALID_SESSION', 'invalid user session');
    }

    this.pendingAuthentications.delete(request.body.sessionId);
    const auth = request.body.authentication;
    const userId = Buffer.from(auth.response.userHandle!, 'base64url');
    const user = this.authStorage.get(userId, auth.id);
    if (!user) {
      throw MessageError.badRequest('NOT_VERIFIED', 'user not verified');
    }

    const verification = await fido2.verifyAuthenticationResponse({
      response: auth,
      expectedChallenge: opData.challenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpId,
      credential: user.credential,
      requireUserVerification: true,
    });
    console.log('AUTH VERIFY', verification);
    return verification;
  }
}

interface RegistrationInitialData {
  username: string;
}

interface RegistrationRequest {
  sessionId: string;
  registration: fido2.RegistrationResponseJSON;
}

interface PendingOperationData {
  timestamp: number;
  challenge: string;
}

interface PendingUserData extends PendingOperationData {
  userId: Uint8Array,
}

interface AuthenticationRequest {
  sessionId: string;
  authentication: fido2.AuthenticationResponseJSON;
}