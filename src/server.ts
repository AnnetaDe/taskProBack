import cors from 'cors';
import path from 'node:path';
import morgan from 'morgan';
import dotenv from 'dotenv';
import express from 'express';
import swaggerUi from 'swagger-ui-express';
import cookieParser from 'cookie-parser';


import authRouter from './routes/authRouter';
import taskRouter from './routes/taskRouter';
import boardRouter from './routes/boardRouter';
import columnRouter from './routes/columnRouter';
import supportRouter from './routes/supportRouter';

import  env  from './helpers/env';
import HttpError from './helpers/HttpError';
import swaggerSpec from './helpers/swagger';

import { Request, Response } from 'express';

const publicDirPath = path.resolve('src', 'public');

dotenv.config();

const startServer = async () => {
  const PORT = env('PORT')||3000;
  const app = express();
  const FRONTEND_URL = env('FRONTEND_URL') || 'http://192.168.1.73:5173';

  console.log(`Server running on port ${PORT}`, `Frontend URL: ${FRONTEND_URL}`, `Public directory: ${publicDirPath}`);

  app.use(express.static(publicDirPath));
  app.use(morgan('tiny'));
    app.use(cookieParser());

  app.use(cors({
    origin: [FRONTEND_URL, 'http://192.168.1.73:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],

  }));
  app.use(express.json());
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.use('/api/auth', authRouter);

  app.use('/api', taskRouter);

  app.use('/api', columnRouter);

  app.use('/api', boardRouter);

  app.use('/api/support', supportRouter);

  app.use((_, res) => {
    res.status(404).json({ message: 'Route not found' });
  });

  app.use((err: HttpError, req: Request, res: Response) => {
    if (err instanceof HttpError) {
      res.status(err.statusCode).json({ message: err.message });
    } else {
      console.log(err);
      res.status(500).json({ message: 'An unexpected error occurred' });
    }
  });

  app.listen(PORT, () => {
    console.log(`server started on ${PORT}`);
  });
};

export default startServer;
