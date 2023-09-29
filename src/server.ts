import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken'
import decode from 'jwt-decode'
import { generateJwtAndRefreshToken } from './auth';
import { auth } from './config';

import { checkRefreshTokenIsValid, invalidateRefreshToken } from './database';
import { CreateSessionDTO, CreateUserData, DecodedToken } from './types';

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cors())


function checkAuthMiddleware(request: Request, response: Response, next: NextFunction) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  const [, token] = authorization?.split(' ');

  if (!token) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  try {
    const decoded = jwt.verify(token as string, auth.secret) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {

    return response
      .status(401)
      .json({ error: true, code: 'token.expired', message: 'Token invalid.' })
  }
}

function addUserInformationToRequest(request: Request, response: Response, next: NextFunction) {
  const { authorization } = request.headers;

  if (!authorization) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  const [, token] = authorization?.split(' ');

  if (!token) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Token not present.' })
  }

  try {
    const decoded = decode(token as string) as DecodedToken;

    request.user = decoded.sub;

    return next();
  } catch (err) {
    return response
      .status(401)
      .json({ error: true, code: 'token.invalid', message: 'Invalid token format.' })
  }
}


// Login
app.post('/sessions', async (request, response) => {
  const { email, password } = request.body as CreateSessionDTO;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user || password !== user.password) {
      return response
        .status(401)
        .json({
          error: true,
          message: 'E-mail or password incorrect.'
        });
    }

    const { token, refreshToken } = await generateJwtAndRefreshToken(email, {
      permissions: user.permissions,
      roles: user.roles,
    });

    return response.json({
      token,
      refreshToken,
      name: user.content,
      ativo: user.ativo,
      id: user.id,
      permissions: user.permissions,
      roles: user.roles,
    });
  } catch (error) {
    return response
      .status(500)
      .json({
        error: true,
        message: 'An error occurred while processing your request.'
      });
  }
});


app.post('/refresh', addUserInformationToRequest, async (request, response) => {
  const email = request.user;
  const { refreshToken } = request.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return response
        .status(401)
        .json({
          error: true,
          message: 'User not found.'
        });
    }

    if (!refreshToken) {
      return response
        .status(401)
        .json({ error: true, message: 'Refresh token is required.' });
    }

    const isValidRefreshToken = await checkRefreshTokenIsValid(email, refreshToken);

    if (!isValidRefreshToken) {
      return response
        .status(401)
        .json({ error: true, message: 'Refresh token is invalid.' });
    }

    await invalidateRefreshToken(email, refreshToken);

    const { token, refreshToken: newRefreshToken } = await generateJwtAndRefreshToken(email, {
      permissions: user.permissions,
      ativo: user.ativo,
      name: user.content,
      roles: user.roles,
    });

    return response.json({
      token,
      refreshToken: newRefreshToken,
      permissions: user.permissions,
      ativo: user.ativo,
      id: user.id,
      name: user.content,
      roles: user.roles,
    });
  } catch (error) {
    return response
      .status(500)
      .json({
        error: true,
        message: 'An error occurred while processing your request.'
      });
  }
});


app.get('/me', checkAuthMiddleware, async (request, response) => {
  const email = request.user;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return response
        .status(400)
        .json({ error: true, message: 'User not found.' });
    }

    return response.json({
      email,
      permissions: user.permissions,
      id: user.id,
      name: user.content,
      ativo: user.ativo,
      roles: user.roles,
    });
  } catch (error) {
    return response
      .status(500)
      .json({
        error: true,
        message: 'An error occurred while processing your request.'
      });
  }
});


// Edicao de usuario Me
app.put('/me/editar', checkAuthMiddleware, async (request, response) => {
  const { email, newPassword, newName } = request.body;

  try {
    // Busque o usuário pelo e-mail
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return response.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Atualize a senha e/ou o nome do usuário, se fornecidos
    if (newPassword) {
      await prisma.user.update({
        where: {
          email,
        },
        data: {
          password: newPassword,
        },
      });
    }

    if (newName) {
      await prisma.user.update({
        where: {
          email,
        },
        data: {
          content: newName,
        },
      });
    }

    response.status(200).json({ success: true, message: 'Dados atualizados com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar os dados do usuário:', error);
    response.status(500).json({ error: 'Erro interno do servidor.' });
  }
});


// Listar Usuários
app.get('/users/all', checkAuthMiddleware, async (request, response) => {
  try {
    const users = await prisma.user.findMany();

    const userData = users.map((user) => ({
      email: user.email,
      permissions: user.permissions,
      id: user.id,
      name: user.content,
      ativo: user.ativo,
      roles: user.roles,
    }));

    return response.json(userData);
  } catch (error) {
    return response.status(500).json({
      error: true,
      message: 'An error occurred while processing your request.',
    });
  }
});

// Desativar ou ativa Usuário
app.patch('/users/:id', checkAuthMiddleware, async (request, response) => {
  const userId = request.params.id;
  const { ativo } = request.body;

  try {
    // Encontre o usuário pelo ID
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      return response.status(404).json({
        error: true,
        message: 'User not found.',
      });
    }

    // Atualize o status "ativo" com base no valor recebido no corpo da requisição
    await prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        ativo,
      },
    });

    const successMessage = ativo ? 'User activated successfully.' : 'User deactivated successfully.';

    return response.status(200).json({
      success: true,
      message: successMessage,
    });
  } catch (error) {
    return response.status(500).json({
      error: true,
      message: 'An error occurred while processing your request.',
    });
  }
});

// Editar dados do Usuário ADM
app.patch('/editUser/:id', async (request, response) => {
  const userId = request.params.id;
  const { name, email, roles } = request.body;

  try {
    // Find the user by ID
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      return response.status(404).json({
        error: true,
        message: 'User not found.',
      });
    }

    // Update the user's data
    await prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        content: name,
        email,
        roles: { set: roles },
      },
    });

    return response.status(200).json({
      success: true,
      message: 'User updated successfully.',
    });
  } catch (error) {
    return response.status(500).json({
      error: true,
      message: 'An error occurred while processing your request.',
    });
  }
});



// Resetar Senha
app.patch('/users/reset-password/:id', checkAuthMiddleware, async (request, response) => {
  const { id } = request.params;

  try {
    // Verifique se o usuário com o ID fornecido existe
    const user = await prisma.user.findUnique({
      where: {
        id,
      },
    });

    if (!user) {
      return response.status(404).json({
        error: true,
        message: 'Usuário não encontrado.',
      });
    }

    // Atualize a senha do usuário para "12345"
    const updatedUser = await prisma.user.update({
      where: {
        id,
      },
      data: {
        password: '12345',
      },
    });

    return response.status(200).json({
      success: true,
      message: 'Senha do usuário atualizada com sucesso para "12345".',
      updatedUser,
    });
  } catch (error) {
    return response.status(500).json({
      error: true,
      message: 'Ocorreu um erro ao processar a solicitação.',
    });
  }
});


// Criar usuário
app.post('/createUser', checkAuthMiddleware, async (request, response) => {
  const { email, name, password, roles } = request.body as CreateUserData;

  try {
    const user = await prisma.user.create({
      data: {
        ativo: true,
        email,
        content: name,
        password,
        roles,
      },
    });

    // Return a success message
    return response.json({
      success: true,
      message: 'User created successfully!',
      user,
    });
  } catch (error) {
    console.error('Error creating user:', error);
    return response.status(500).json({
      error: true,
      message: 'An error occurred while processing your request.',
    });
  }
});





app.listen(3333);