/*
  Warnings:

  - Added the required column `ativo` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "ativo" BOOLEAN NOT NULL,
ADD COLUMN     "avatar" TEXT;
