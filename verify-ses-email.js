/**
 * AWS SES Email Verification Script
 * 
 * This script verifies an email address in AWS SES so you can send emails from it.
 * AWS SES requires email verification when in sandbox mode.
 * 
 * Usage: node verify-ses-email.js your-email@example.com
 */

require('dotenv').config();
const AWS = require('aws-sdk');

// Configure AWS SES
const ses = new AWS.SES({
  apiVersion: '2010-12-01',
  region: process.env.AWS_SES_REGION || 'us-east-1'
});

const emailToVerify = process.argv[2];

if (!emailToVerify) {
  console.error('❌ Error: Please provide an email address to verify');
  console.log('\nUsage: node verify-ses-email.js your-email@example.com');
  console.log('\nExample: node verify-ses-email.js ankitap07sahoo@gmail.com');
  process.exit(1);
}

// Validate email format
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
if (!emailRegex.test(emailToVerify)) {
  console.error('❌ Error: Invalid email format');
  process.exit(1);
}

console.log('\n📧 AWS SES Email Verification\n');
console.log('=' .repeat(60));

async function verifyEmail() {
  try {
    console.log(`\n🔍 Checking if ${emailToVerify} is already verified...`);
    
    // Check current verification status
    const identities = await ses.listIdentities({ IdentityType: 'EmailAddress' }).promise();
    const verificationAttrs = await ses.getIdentityVerificationAttributes({
      Identities: identities.Identities
    }).promise();
    
    const status = verificationAttrs.VerificationAttributes[emailToVerify];
    
    if (status && status.VerificationStatus === 'Success') {
      console.log(`✅ ${emailToVerify} is already verified!`);
      console.log('\n📝 You can now use this email in your .env file:');
      console.log(`   EMAIL_FROM=${emailToVerify}`);
      return;
    }
    
    if (status && status.VerificationStatus === 'Pending') {
      console.log(`⏳ ${emailToVerify} verification is pending.`);
      console.log('   Check your inbox for the verification email.');
      return;
    }
    
    // Email not verified, send verification request
    console.log(`\n📤 Sending verification email to ${emailToVerify}...`);
    
    const result = await ses.verifyEmailIdentity({
      EmailAddress: emailToVerify
    }).promise();
    
    console.log('\n✅ Verification email sent successfully!');
    console.log('\n📬 Next Steps:');
    console.log(`   1. Check your inbox at ${emailToVerify}`);
    console.log('   2. Click the verification link in the email from AWS');
    console.log('   3. Wait for verification to complete (usually takes a few seconds)');
    console.log('   4. Update your .env file:');
    console.log(`      EMAIL_FROM=${emailToVerify}`);
    console.log('   5. Redeploy your application');
    
    console.log('\n⏱️  The verification email may take a few minutes to arrive.');
    console.log('   Check your spam folder if you don\'t see it.');
    
  } catch (error) {
    console.error('\n❌ Error verifying email:', error.message);
    
    if (error.code === 'InvalidParameterValue') {
      console.log('\n💡 The email address format is invalid.');
    } else if (error.code === 'AccessDenied' || error.code === 'AccessDeniedException') {
      console.log('\n💡 Your AWS credentials don\'t have SES permissions.');
      console.log('   Required IAM permissions:');
      console.log('   - ses:VerifyEmailIdentity');
      console.log('   - ses:GetIdentityVerificationAttributes');
      console.log('   - ses:ListIdentities');
    } else if (error.code === 'InvalidClientTokenId') {
      console.log('\n💡 AWS credentials are invalid or not configured.');
      console.log('   Check your .env file or AWS credentials file.');
    } else {
      console.log('\n💡 Error Details:', error);
    }
    
    process.exit(1);
  }
}

async function checkSESStatus() {
  try {
    console.log('\n📊 Checking your AWS SES account status...\n');
    
    const accountInfo = await ses.getAccountSendingEnabled().promise();
    console.log(`   Sending Enabled: ${accountInfo.Enabled ? '✅ Yes' : '❌ No'}`);
    
    // Get send statistics
    const stats = await ses.getSendStatistics().promise();
    if (stats.SendDataPoints && stats.SendDataPoints.length > 0) {
      const totalSent = stats.SendDataPoints.reduce((sum, point) => sum + point.DeliveryAttempts, 0);
      console.log(`   Emails Sent (24h): ${totalSent}`);
    }
    
    // Check if in sandbox
    console.log('\n📦 Sandbox Status:');
    console.log('   AWS SES starts in sandbox mode, which means:');
    console.log('   - You can only send to verified email addresses');
    console.log('   - Limited to 200 emails per day');
    console.log('   - Maximum 1 email per second');
    console.log('\n   To exit sandbox mode:');
    console.log('   1. Go to AWS SES Console');
    console.log('   2. Request production access');
    console.log('   3. Provide use case information');
    console.log('   4. Wait for approval (usually 24 hours)');
    
  } catch (error) {
    console.log('   Unable to retrieve account status');
  }
}

async function main() {
  await checkSESStatus();
  await verifyEmail();
  
  console.log('\n' + '='.repeat(60));
  console.log('\n💡 Quick Tips:');
  console.log('   - Use your personal Gmail for testing: ankitap07sahoo@gmail.com');
  console.log('   - Verify multiple emails if needed');
  console.log('   - For production, use a custom domain email');
  console.log('   - Consider using AWS Cognito for automatic email handling');
  console.log('\n');
}

main();
