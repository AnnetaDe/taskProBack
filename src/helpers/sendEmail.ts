import dotenv from 'dotenv';
dotenv.config();
import nodemailer from 'nodemailer';
import { SentMessageInfo } from 'nodemailer';

const { EMAIL, EMAIL_PASSWORD } = process.env;

const nodemailerConfig = {
  host: 'smtp.ukr.net',
  port: 465,
  secure: true,
  auth: {
    user: EMAIL,
    pass: EMAIL_PASSWORD,
  },
};

const transport = nodemailer.createTransport(nodemailerConfig);

interface EmailData {
    from?: string;
    to: string;
    subject: string;
    html: string;
}


const sendEmail = (data: EmailData): Promise<SentMessageInfo> => {
    const email: EmailData = { ...data, from: EMAIL };
    return transport.sendMail(email);
};


export default sendEmail;
