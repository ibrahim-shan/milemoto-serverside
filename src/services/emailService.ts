import nodemailer from 'nodemailer';
import sgMail from '@sendgrid/mail';
import { env } from '../config/env.js';
import { logger } from '../utils/logger.js';

// --- This is new: Configure the SendGrid client ---
// We only do this once when the app starts
if (env.SENDGRID_API_KEY) {
  sgMail.setApiKey(env.SENDGRID_API_KEY);
  logger.info('SendGrid mail client configured.');
} else if (env.NODE_ENV === 'production') {
  logger.error('SENDGRID_API_KEY is not set. Emails will not be sent in production.');
}

// --- This is new: Create a "singleton" for the Ethereal transport ---
let etherealTransport: nodemailer.Transporter | null = null;

async function getEtherealTransport() {
  // If we already have one, reuse it
  if (etherealTransport) {
    return etherealTransport;
  }

  // Create a new Ethereal account for this dev session
  const testAccount = await nodemailer.createTestAccount();
  logger.info(
    {
      user: testAccount.user,
      pass: testAccount.pass,
    },
    'Nodemailer test account (Ethereal) created.'
  );

  etherealTransport = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user, // Ethereal user
      pass: testAccount.pass, // Ethereal password
    },
  });
  return etherealTransport;
}
/**
 * Sends an email verification link.
 */
export async function sendVerificationEmail(toEmail: string, verifyUrl: string) {
  const mailOptions = {
    from: '"MileMoto" <milemotoauto@gmail.com>',
    to: toEmail,
    subject: 'Please Verify Your Email Address',
    html: `
      <p>Thanks for signing up for MileMoto!</p>
      <p>Please click this link to verify your email address:</p>
      <a href="${verifyUrl}" target="_blank" style="font-size: 16px; font-family: Arial, sans-serif; color: #ffffff; text-decoration: none; border-radius: 5px; background-color: #155eef; border: 1px solid #155eef; padding: 10px 20px; display: inline-block;">Verify Email</a>
      <p style="margin-top: 20px;">Or copy and paste this URL into your browser:</p>
      <p>${verifyUrl}</p>
    `,
    text: `Thanks for signing up for MileMoto! Please click this link to verify your email address: ${verifyUrl}`,
  };

  if (env.NODE_ENV === 'production' && env.SENDGRID_API_KEY) {
    // --- Production: Use SendGrid ---
    try {
      await sgMail.send(mailOptions);
      logger.info({ to: toEmail }, 'Verification email sent (SendGrid)');
    } catch (error: unknown) {
      // Type guard for SendGrid errors
      if (error && typeof error === 'object' && 'response' in error) {
        const sgError = error as { response?: { body?: string } };
        logger.error({ err: sgError.response?.body }, 'SendGrid error');
      } else {
        logger.error({ err: error }, 'SendGrid error');
      }
      throw new Error('Failed to send email');
    }
  } else {
    // --- Development: Use Ethereal ---
    const transport = await getEtherealTransport();
    const info = await transport.sendMail(mailOptions);

    logger.info({ messageId: info.messageId }, 'Verification email sent (Ethereal)');
    logger.info(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
  }
}

/**
 * Sends a password reset email.
 */
export async function sendPasswordResetEmail(toEmail: string, resetUrl: string) {
  const mailOptions = {
    // IMPORTANT: This "from" email must be a verified sender in your SendGrid account
    from: '"MileMoto" <milemotoauto@gmail.com>',
    to: toEmail,
    subject: 'Your Password Reset Link',
    html: `
      <p>You requested a password reset.</p>
      <p>Click this link to reset your password (link is valid for 1 hour):</p>
      <a href="${resetUrl}" target="_blank" style="font-size: 16px; font-family: Arial, sans-serif; color: #ffffff; text-decoration: none; border-radius: 5px; background-color: #155eef; border: 1px solid #155eef; padding: 10px 20px; display: inline-block;">Reset Password</a>
      <p style="margin-top: 20px;">Or copy and paste this URL into your browser:</p>
      <p>${resetUrl}</p>
    `,
    text: `You requested a password reset. Click this link to reset your password (link is valid for 1 hour): ${resetUrl}`,
  };

  // --- THIS IS THE NEW LOGIC ---
  if (env.NODE_ENV === 'production' && env.SENDGRID_API_KEY) {
    // --- Production: Use SendGrid ---
    try {
      await sgMail.send(mailOptions);
      logger.info({ to: toEmail }, 'Password reset email sent (SendGrid)');
    } catch (error: unknown) {
      // Type guard for SendGrid errors
      if (error && typeof error === 'object' && 'response' in error) {
        const sgError = error as { response?: { body?: string } };
        logger.error({ err: sgError.response?.body }, 'SendGrid error');
      } else {
        logger.error({ err: error }, 'SendGrid error');
      }
      // Re-throw the error so auth.route.ts knows it failed
      throw new Error('Failed to send email');
    }
  } else {
    // --- Development: Use Ethereal ---
    const transport = await getEtherealTransport();
    const info = await transport.sendMail(mailOptions);

    logger.info({ messageId: info.messageId }, 'Password reset email sent (Ethereal)');
    // Get the Ethereal preview URL
    logger.info(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
  }
}
