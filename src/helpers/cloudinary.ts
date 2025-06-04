import env from './env';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';

dotenv.config();

const cloud_name = env('CLOUDINARY_NAME');
const api_key = env('CLOUDINARY_API_KEY');
const api_secret = env('CLOUDINARY_API_SECRET');

if(!cloud_name) {
  throw new Error('CLOUDINARY_NAME is not defined in environment variables');
}
if(!api_key) {
  throw new Error('CLOUDINARY_API_KEY is not defined in environment variables');
}
if(!api_secret) {
  throw new Error('CLOUDINARY_API_SECRET is not defined in environment variables');
}

cloudinary.config({
  cloud_name,
  api_key,
  api_secret,
});

export default cloudinary;
