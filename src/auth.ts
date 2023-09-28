import jwt from 'jsonwebtoken'

import { auth } from './config';
import { createRefreshToken } from './database';

export async function generateJwtAndRefreshToken(email: string, payload: object = {}) {
  const token = jwt.sign(payload, auth.secret, {
    subject: email,
    expiresIn: 2880, // 15 minutes
  });

  const refreshToken = await createRefreshToken(email);

  return {
    token,
    refreshToken,
  }
}
