
import jwt from 'jsonwebtoken';
import env from '../helpers/env.js';
import { findSession } from '../services/authServices';



const JWT_SECRET = env('JWT_SECRET');
const JWT_SECRET_REFRESH = env('JWT_SECRET_REFRESH');

export const checkAuthToken = (token: string | undefined): boolean => {
    if (!token || !token.startsWith('Bearer ')) return false;
  
    const rawToken = token.split(' ')[1];
    if (!rawToken) return false;
  
    try {
      if (!JWT_SECRET) throw new Error('JWT secret is not defined');
  
      const decoded = jwt.verify(rawToken, JWT_SECRET) as jwt.JwtPayload;
  
      return typeof decoded.id === 'string' && decoded.id.length > 0;
    } catch {
      return false;
    }
  };


export const checkRefreshToken = async (token: string | undefined): Promise<boolean> => {
    if (!token || !token.startsWith('Bearer ')) return false;
  
    const rawToken = token.split(' ')[1];
    if (!rawToken) return false;
  
    try {
      if (!JWT_SECRET_REFRESH) throw new Error('JWT refresh secret is not defined');
  
      const decoded = jwt.verify(rawToken, JWT_SECRET_REFRESH) as jwt.JwtPayload;
      const decodedId = decoded.id;
        if (typeof decodedId !== 'string' || decodedId.length === 0) {
            return false;
        }
        const session = await findSession({ userId: decodedId });

        return !!session && session.refreshToken === rawToken;

    } catch {
      return false;
    }
  };