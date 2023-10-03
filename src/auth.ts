import jwt from 'jsonwebtoken'

import { auth } from './config';
import { createRefreshToken } from './database';

export async function generateJwtAndRefreshToken(email: string, payload: object = {}) {
  const token = jwt.sign(payload, auth.secret, {
    subject: email,
    expiresIn: 28800,
  });

  const refreshToken = await createRefreshToken(email);

  return {
    token,
    refreshToken,
  }
}
