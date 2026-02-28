const nodemailer = require('nodemailer');
const AWS = require('aws-sdk');

// Configure AWS SES
const ses = new AWS.SES({
  apiVersion: '2010-12-01',
  region: process.env.AWS_SES_REGION || 'us-east-1'
});

// Configure email transporter
// For production, use AWS SES or other email service
const createTransporter = () => {
  console.log('Creating email transporter...');
  
  // AWS SES Configuration (Recommended for production)
  if (process.env.AWS_SES_REGION) {
    console.log('Using AWS SES for email delivery (direct)');
    
    // Return null to use direct SES sending
    return null;
  }
  
  // Fallback to SMTP (for development/testing)
  // Configure these in your environment variables
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    console.log('Using SMTP for email delivery');
    return nodemailer.createTransporter({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  
  // No email configuration found
  console.warn('⚠️  WARNING: No email configuration found!');
  console.warn('Please set either:');
  console.warn('  1. AWS_SES_REGION and EMAIL_FROM for AWS SES');
  console.warn('  2. SMTP_HOST, SMTP_USER, SMTP_PASS for SMTP');
  
  // Return a mock transporter for development
  return nodemailer.createTransport({
    streamTransport: true,
    newline: 'unix',
    buffer: true
  });
};

/**
 * Generate a 6-digit OTP
 */
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Generate OTP expiry time (5 minutes from now)
 */
const generateOTPExpiry = () => {
  return new Date(Date.now() + 5 * 60 * 1000).toISOString();
};

/**
 * Send OTP email for signup verification
 */
const sendSignupOTP = async (email, otp) => {
  console.log(`📧 Attempting to send signup OTP to: ${email}`);
  console.log(`EMAIL_FROM configured as: ${process.env.EMAIL_FROM || 'noreply@myvision.com'}`);
  console.log(`AWS_SES_REGION: ${process.env.AWS_SES_REGION || 'not set'}`);
  
  // Validate configuration
  if (!process.env.EMAIL_FROM) {
    console.error('❌ EMAIL_FROM environment variable is not set!');
    return { 
      success: false, 
      error: 'EMAIL_FROM not configured. Please set in .env file.' 
    };
  }
  
  const transporter = createTransporter();
  
  // If using direct SES (no transporter), use AWS SDK directly
  if (!transporter && process.env.AWS_SES_REGION) {
    console.log('📤 Using AWS SES to send email...');
    
    const params = {
      Source: process.env.EMAIL_FROM,
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Subject: {
          Data: 'Verify Your Email - MyVision',
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Email Verification</h2>
                <p>Thank you for signing up! Please use the following OTP to verify your email address:</p>
                <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                  ${otp}
                </div>
                <p style="color: #666;">This code will expire in <strong>5 minutes</strong>.</p>
                <p style="color: #666;">If you didn't request this, please ignore this email.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #999; font-size: 12px;">MyVision - Secure Authentication System</p>
              </div>
            `,
            Charset: 'UTF-8'
          }
        }
      }
    };
    
    try {
      const result = await ses.sendEmail(params).promise();
      console.log(`✅ Signup OTP sent successfully to ${email}`);
      console.log(`Message ID: ${result.MessageId}`);
      return { success: true, messageId: result.MessageId };
    } catch (error) {
      console.error('❌ Error sending signup OTP:', {
        code: error.code,
        message: error.message,
        statusCode: error.statusCode,
        requestId: error.requestId
      });
      
      // Provide specific error messages
      let errorMessage = error.message;
      if (error.code === 'MessageRejected') {
        errorMessage = `Email address ${process.env.EMAIL_FROM} is not verified in AWS SES. Run: node verify-ses-email.js ${process.env.EMAIL_FROM}`;
      } else if (error.code === 'InvalidParameterValue') {
        errorMessage = 'Invalid email address format or unverified sender email.';
      } else if (error.code === 'AccessDenied' || error.code === 'AccessDeniedException') {
        errorMessage = 'AWS credentials lack SES permissions. Check IAM policy.';
      } else if (error.code === 'ServiceUnavailable') {
        errorMessage = 'AWS SES service is temporarily unavailable. Please try again.';
      }
      
      return { success: false, error: errorMessage, code: error.code };
    }
  }
  
  // Otherwise use nodemailer transporter
  const mailOptions = {
    from: process.env.EMAIL_FROM || 'noreply@myvision.com',
    to: email,
    subject: 'Verify Your Email - MyVision',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Thank you for signing up! Please use the following OTP to verify your email address:</p>
        <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
          ${otp}
        </div>
        <p style="color: #666;">This code will expire in <strong>5 minutes</strong>.</p>
        <p style="color: #666;">If you didn't request this, please ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 12px;">MyVision - Secure Authentication System</p>
      </div>
    `,
  };
  
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Signup OTP sent successfully to ${email}`);
    console.log(`Message ID: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Error sending signup OTP via SMTP:', {
      code: error.code,
      message: error.message,
      command: error.command
    });
    return { success: false, error: error.message, code: error.code };
  }
};

/**
 * Send OTP email for suspicious login verification
 */
const sendLoginOTP = async (email, otp, reason) => {
  console.log(`📧 Attempting to send login OTP to: ${email}`);
  console.log(`Reason: ${reason}`);
  
  const transporter = createTransporter();
  
  // If using direct SES (no transporter), use AWS SDK directly
  if (!transporter && process.env.AWS_SES_REGION) {
    const params = {
      Source: process.env.EMAIL_FROM || 'noreply@myvision.com',
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Subject: {
          Data: 'Suspicious Login Attempt Detected - MyVision',
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #d9534f;">Suspicious Login Detected</h2>
                <p>We detected an unusual login attempt to your account.</p>
                <p style="color: #666;"><strong>Reason:</strong> ${reason}</p>
                <p>If this is you, please use the following OTP to verify your identity:</p>
                <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                  ${otp}
                </div>
                <p style="color: #666;">This code will expire in <strong>5 minutes</strong>.</p>
                <p style="color: #d9534f;"><strong>If this wasn't you, please secure your account immediately by changing your password.</strong></p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #999; font-size: 12px;">MyVision - Secure Authentication System</p>
              </div>
            `,
            Charset: 'UTF-8'
          }
        }
      }
    };
    
    try {
      const result = await ses.sendEmail(params).promise();
      console.log(`✅ Login OTP sent successfully to ${email}`);
      console.log(`Message ID: ${result.MessageId}`);
      return { success: true, messageId: result.MessageId };
    } catch (error) {
      console.error('❌ Error sending login OTP:', {
        code: error.code,
        message: error.message,
        statusCode: error.statusCode,
        requestId: error.requestId
      });
      
      let errorMessage = error.message;
      if (error.code === 'MessageRejected') {
        errorMessage = `Email not verified in AWS SES. Run: node verify-ses-email.js ${process.env.EMAIL_FROM}`;
      }
      
      return { success: false, error: errorMessage, code: error.code };
      return { success: false, error: error.message };
    }
  }
  
  // Otherwise use nodemailer transporter
  const mailOptions = {
    from: process.env.EMAIL_FROM || 'noreply@myvision.com',
    to: email,
    subject: 'Suspicious Login Attempt Detected - MyVision',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #d9534f;">Suspicious Login Detected</h2>
        <p>We detected an unusual login attempt to your account.</p>
        <p style="color: #666;"><strong>Reason:</strong> ${reason}</p>
        <p>If this is you, please use the following OTP to verify your identity:</p>
        <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
          ${otp}
        </div>
        <p style="color: #666;">This code will expire in <strong>5 minutes</strong>.</p>
        <p style="color: #d9534f;"><strong>If this wasn't you, please secure your account immediately by changing your password.</strong></p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 12px;">MyVision - Secure Authentication System</p>
      </div>
    `,
  };
  
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Login OTP sent successfully to ${email}`);
    console.log(`Message ID: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Error sending login OTP:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Validate OTP expiry
 */
const isOTPExpired = (otpExpiry) => {
  if (!otpExpiry) return true;
  return new Date() > new Date(otpExpiry);
};

module.exports = {
  generateOTP,
  generateOTPExpiry,
  sendSignupOTP,
  sendLoginOTP,
  isOTPExpired,
};
