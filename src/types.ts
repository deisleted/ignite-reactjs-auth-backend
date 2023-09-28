export type CreateSessionDTO = {
  email: string;
  password: string;
}

type UserData = {
  password: string;
  permissions: string[];
  roles: string[];
}


export type CreateUserData = {
  password: string;
  email: string;
  roles: string[];
  name: string;
}

export type UsersStore = Map<string, UserData>

export type refreshToken = Map<string, string[]>

export type DecodedToken = {
  sub: string;
}