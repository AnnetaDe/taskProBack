import HttpError from '../helpers/HttpError';
import { findSession, findUser } from '../services/authServices';
import { Controller } from '../types';
import { checkAuthToken } from '../helpers/checkToken';



// This middleware checks for a valid JWT token in the request headers or cookies,
// verifies it, and retrieves the user information. If the token is valid, it attaches
// the user information to the request object.
// export const authenticate: Controller = async (req, res, next) => {
//   try {
// 
//     const token =
//   req.headers.authorization?.startsWith('Bearer ')
//     ? req.headers.authorization.split(' ')[1]
//     : req.cookies?.token;
// 
//     console.log('Token:', req.headers.authorization);
//     console.log('Cookie Token:', req.cookies);
//  
//     if (!token) {
//       throw new HttpError(401, 'Authentication token not found');
//     }
// 
//     const JWT_SECRET = env('JWT_SECRET');
// 
//     if (!JWT_SECRET) {
//       throw new HttpError(500, 'JWT secret is not defined');
//     }
// 
//     // Verify the JWT token and extract the user ID
//     let decoded;
//     try {
//       decoded = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
//     } catch {
//       throw new HttpError(401, 'Invalid or expired token');
//     }
//     if (!decoded || !decoded.id) {
//       throw new HttpError(401, 'Invalid token payload');
//     }
// 
// 
//     const { id } = jwt.verify(token, JWT_SECRET as string) as jwt.JwtPayload;
// 
//     const user = await findUser({ _id: id });
// 
//     if (!user) {
//       throw new HttpError(401, 'User not found');
//     }
// 
//     const session = await findSession({ userId: id });
// 
//     if (!session) {
//       throw new HttpError(401, 'User already logged out');
//     }
// 
//     const { _id, username, email, avatarUrl, theme, isVerified } = user;
// 
//     req.user = {
//       _id,
//       username,
//       email,
//       avatarUrl,
//       theme,
//       isVerified,
//     
//     };
// 
//     next();
//   } catch (error) {
//     if (error instanceof Error) {
//       next(new HttpError(401, error.message));
//     } else {
//       next(error);
//     }
//   }
// };
// 

export const authenticate: Controller = async (req, res, next) => {
  try {
    const bearerToken = req.headers.authorization || `Bearer ${req.cookies?.token}`;
    const userId = checkAuthToken(bearerToken);
    if (!userId) {
      throw new HttpError(401, 'Authentication token not found or invalid');
    }
    const user = await findUser({ _id: userId });
    if (!user) {
      throw new HttpError(401, 'User not found');
    }
    const session = await findSession({ userId: user._id });
    if (!session) {
      throw new HttpError(401, 'User already logged out');
    }
    const { _id, username, email, avatarUrl, theme, isVerified } = user;
    req.user = {
      _id,
      username,
      email,
      avatarUrl,
      theme,
      isVerified,
    };
    next();
  } catch (error) {
    if (error instanceof Error) {
      next(new HttpError(401, error.message));
    } else {
      next(error);
    }
  }
}
