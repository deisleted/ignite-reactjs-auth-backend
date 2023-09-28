import { refreshToken, UsersStore } from "./types"
import { Prisma, PrismaClient } from '@prisma/client';

import { v4 as uuid } from 'uuid'



const prisma = new PrismaClient();



export async function createRefreshToken(email: string) {
  try {
    const refreshToken = uuid();

    await prisma.refreshToken.create({
      data: {
        email,
        token: refreshToken,
      },
    });

    return refreshToken;
  } catch (error: any) {
    throw new Error('Failed to create refresh token: ' + error.message);
  }
}


export async function checkRefreshTokenIsValid(email: string, refreshToken: string) {
  try {
    const storedRefreshTokens = await prisma.refreshToken.findFirst({
      where: {
        email,
        token: refreshToken,
      },
    });
    return storedRefreshTokens !== null;
  } catch (error: any) {
    throw new Error('Failed to check refresh token validity: ' + error.message);
  }
}



export async function invalidateRefreshToken(email: string, refreshToken: string) {
  try {
    await prisma.refreshToken.deleteMany({
      where: {
        email,
        token: refreshToken,
      },
    });
  } catch (error: any) {
    throw new Error('Failed to invalidate refresh token: ' + error.message);
  }
}



