import fs from 'node:fs/promises';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import axios from 'axios';
import bcrypt from 'bcrypt';
import queryString from 'query-string';
import { nanoid } from 'nanoid';

import * as authServices from '../services/authServices';

import HttpError from '../helpers/HttpError';
import cloudinary from '../helpers/cloudinary';
import ctrlWrapper from '../decorators/ctrlWrapper';
import env from '../helpers/env';
// Make sure the sendMail helper exists at the specified path or update the path accordingly
// If the file does not exist, create it at ../helpers/sendMail.ts with the appropriate implementation.
import { Controller } from '../types';
import sendEmail from '../helpers/sendEmail';
import { checkRefreshToken } from '../helpers/checkToken';

const registerUser: Controller = async (req, res) => {
  const { username, email, password } = req.body;

  const user = await authServices.findUser({ email });

  if (user) {
    throw new HttpError(409, 'Email already in use');
  }

  const hashPassword = await bcrypt.hash(password, 10);

  const verificationCode = nanoid(12);

  const newUser = await authServices.registerUser({
    username,
    email,
    password: hashPassword,
    verificationToken: verificationCode,
  });

  const BASE_URL = env('BASE_URL');

  const data = {
    to: email,
    subject: 'Confirm your registration in TaskPro app',
    text: 'Press on the link to confirm your email',
    html: `Good day! Please click on the following link to confirm your account in TaskPro app. <a href="${BASE_URL}/auth/verify/${verificationCode}" target="_blank" rel="noopener noreferrer">Confirm my mail</a>`,
  };

  sendEmail(data);

  res.json({
    status: 201,
    message: 'User successfully registered',
    data: {
      username: newUser.username,
      email: newUser.email,
    },
  });
};

const loginUser: Controller = async (req, res) => {
  const { email, password } = req.body;

  const JWT_SECRET = env('JWT_SECRET');
  const JWT_SECRET_REFRESH = env('JWT_SECRET_REFRESH');


  if (!JWT_SECRET || !JWT_SECRET_REFRESH) {
    throw new Error('JWT_SECRET environment variable is not set');
  }

  const user = await authServices.findUser({ email });

  if (!user) {
    throw new HttpError(400, 'Email or password invalid');
  }

  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw new HttpError(400, 'Email or password invalid');
  }

  if (!user.isVerified) {
    throw new HttpError(
      403,
      'User mail is not verified, please check your mail for following instructions'
    );
  }
  const payload = { id: user._id };
  const token = jwt.sign(payload, JWT_SECRET);
  const refreshToken = jwt.sign(
    payload,
    JWT_SECRET_REFRESH,
  );
    const isProd = process.env.NODE_ENV === 'production';

  const session = await authServices.createSession({
    userId: user._id,
    accessToken: token,
    refreshToken: refreshToken, 
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: isProd? true : false,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 3600000, 
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd ? true : false,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 86400000,
  });

  res.cookie('sid', String(session._id), {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 86400000,
  });
  res.json({
    status: 200,
    data: {
      token,
      refreshToken,
      sessionId: session._id,
      user: {
        username: user.username,
        email: user.email,
        avatarUrl: user.avatarUrl,
        theme: user.theme,
      },
    },
  });
};

const logoutUser: Controller = async (req, res) => {
  const { _id } = req.user as { _id: string };
  await authServices.abortUserSession({ userId: _id });
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie('token', {
    httpOnly: true,
    secure: isProd ? true : false,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 3000000, // 1 hour
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd ? true : false,
    maxAge: 86400000,
  });
  res.clearCookie('sid', {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd ? true : false,
    maxAge: 86400000,
  });
  res.json({
    status: 204,
    message: 'User successfully logged out',
  });
};

const getCurrentUser: Controller = async (req, res) => {
  console.log('Current user:', req.user);
  const { email, username, avatarUrl, theme } = req.user as {
    email: string;
    username: string;
    avatarUrl: string | null;
    theme: string;
  };

  res.json({
    status: 200,
    data: { username, email, avatarUrl, theme },
  });
};

const patchUser: Controller = async (req, res) => {
  const { username, email, password, theme } = req.body;
  const { _id } = req.user as {
    _id: unknown;
  };

  let hashPassword;
  let verificationToken;
  let isVerified;
  let avatarUrl;

  if (password) {
    hashPassword = await bcrypt.hash(password, 10);
  }

  if (email) {
    const userWithNewMail = await authServices.findUser({ email });
    if (userWithNewMail) {
      throw new HttpError(
        408,
        'Cannot change email to that which is already in use.'
      );
    }

    const BASE_URL = env('BASE_URL');

    verificationToken = nanoid(12);
    isVerified = false;

    const data = {
      to: email,
      subject: 'Confirm your registration in TaskPro app',
      text: 'Press on the link to confirm your email',
      html: `Good day! Please click on the following link to confirm your account in TaskPro app. <a href="${BASE_URL}/auth/verify/${verificationToken}" target="_blank" rel="noopener noreferrer">Confirm my mail</a>`,
    };

    sendEmail(data);
  }

  if (req?.file?.path) {
    
    try {
      const { secure_url } = await cloudinary.uploader.upload(req.file.path, {
        folder: 'taskPro',
      });

      avatarUrl = secure_url;

      await fs.unlink(req.file.path);
    } catch (error) {
      await fs.unlink(req.file.path);

      throw error;
    }
  }

  const newUser = await authServices.updateUser(
    { _id },
    {
      username,
      email,
      password: hashPassword,
      theme,
      avatarUrl,
      isVerified,
      verificationToken,
    }
  );

  res.json({
    status: 200,
    data: {
      username: newUser?.username,
      email: newUser?.email,
      theme: newUser?.theme,
      avatarUrl: newUser?.avatarUrl,
    },
  });
};

const verifyUser: Controller = async (req, res) => {
  const { verificationToken } = req.params;

  const user = await authServices.findUser({
    verificationToken,
  });

  if (!user) {
    throw new HttpError(400, 'Invalid verification token');
  }

  if (user.isVerified) {
    throw new HttpError(400, 'Verification has already been passed');
  }

  await authServices.updateUser(
    { verificationToken },
    { verificationToken: 'User verified', isVerified: true }
  );

  const root = path.resolve('src', 'constants');

  res.sendFile('htmlPage.html', { root });
};

const resendVerifyMessage: Controller = async (req, res) => {
  const { email } = req.body;

  const user = await authServices.findUser({
    email,
  });

  if (!user) {
    throw new HttpError(400, 'Invalid verification token');
  }

  if (user.isVerified) {
    throw new HttpError(400, 'Verification has already been passed');
  }

  const verificationToken = nanoid(12);

  await authServices.updateUser({ email }, { verificationToken });

  const BASE_URL = env('BASE_URL');

  const data = {
    to: email,
    subject: 'Confirm your registration in TaskPro app',
    text: 'Press on the link to confirm your email',
    html: `Good day! Please click on the following link to confirm your account in TaskPro app. <a href="${BASE_URL}/auth/verify/${verificationToken}" target="_blank" rel="noopener noreferrer">Confirm my mail</a>`,
  };

  sendEmail(data);

  res.json({
    status: 200,
    message: 'New verification email sent',
  });
};

const refreshTokens: Controller = async (req, res) => {

  const JWT_SECRET = env('JWT_SECRET');
  const JWT_SECRET_REFRESH = env('JWT_SECRET_REFRESH');
  if (!JWT_SECRET_REFRESH) {
    throw new Error('JWT_SECRET_REFRESH environment variable is not set');
  }


  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is not set');
  }

  const bearer = req.headers.authorization;
  const refreshId = checkRefreshToken(bearer);

  if (!refreshId) {
    throw new HttpError(401, 'Invalid or missing refresh token');
  }
  const rawToken = bearer!.split(' ')[1];

const session = await authServices.findSession({ userId: refreshId });
  if (!session || session.refreshToken !== rawToken) {
    throw new HttpError(401, 'Refresh session invalid or expired');
  }

  const payload = { id: refreshId };
  const newAccessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  const newRefreshToken = jwt.sign(payload, JWT_SECRET_REFRESH, { expiresIn: '7d' });
  await authServices.createSession({
    userId: refreshId,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
  const isProd = process.env.NODE_ENV === 'production';

  res.cookie('token', newAccessToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 3600000,
  });

  res.cookie('refreshToken', newRefreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 86400000,
  });

  res.json({
    status: 200,
    data: {
      token: newAccessToken,
      refreshToken: newRefreshToken,
    },
  });

  
};

const googleAuth: Controller = async (req, res) => {
  const stringifiedParams = queryString.stringify({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: `${env('BASE_URL')}/auth/google-redirect`,
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ].join(' '),
    response_type: 'code',
    access_type: 'offline',
    prompt: 'consent',
  });

  return res.redirect(
    `https://accounts.google.com/o/oauth2/v2/auth?${stringifiedParams}`
  );
};

const googleRedirect: Controller = async (req, res) => {
  const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  const urlObj = new URL(fullUrl);
  const urlParams = queryString.parse(urlObj.search);
  const code = urlParams.code;

  const tokenData = await axios.post(`https://oauth2.googleapis.com/token`, {
    client_id: env('GOOGLE_CLIENT_ID'),
    client_secret: env('GOOGLE_CLIENT_SECRET'),
    redirect_uri: `${env('BASE_URL')}/auth/google-redirect`,
    grant_type: 'authorization_code',
    code,
  });

  const { data: googleUser } = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: {
      Authorization: `Bearer ${tokenData.data.access_token}`,
    },
  });

  const { email, name, picture, id } = googleUser;

  const JWT_SECRET = env('JWT_SECRET');

  let user = await authServices.findUser({ email });

  if (!user) {
    const hashedPassword = await bcrypt.hash(id, 10);

    user = await authServices.registerUser({
      username: name,
      email,
      password: hashedPassword,
      verificationToken: null,
      isVerified: true,
      avatarUrl: picture,
    });
  }

  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable is not set');
  }

  const token = jwt.sign({ id: user._id }, JWT_SECRET, );

  return res.redirect(`${env('FRONTEND_URL')}?token=${token}`);
};

export default {
  registerUser: ctrlWrapper(registerUser),
  loginUser: ctrlWrapper(loginUser),
  logoutUser: ctrlWrapper(logoutUser),
  verifyUser: ctrlWrapper(verifyUser),
  getCurrentUser: ctrlWrapper(getCurrentUser),
  patchUser: ctrlWrapper(patchUser),
  resendVerifyMessage: ctrlWrapper(resendVerifyMessage),
  refreshTokens: ctrlWrapper(refreshTokens),
  googleAuth: ctrlWrapper(googleAuth),
  googleRedirect: ctrlWrapper(googleRedirect),
};
