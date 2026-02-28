/**
 * Cognito Configuration Diagnostic Tool
 * 
 * This script checks your Cognito configuration and identifies issues.
 * 
 * Usage: node diagnose-cognito.js
 */

// Try to load dotenv if available (for local testing)
try {
  require('dotenv').config();
} catch (e) {
  console.log('Note: dotenv not installed. Using existing environment variables.');
}

const AWS = require('aws-sdk');

console.log('\n🔍 AWS Cognito Configuration Diagnostic\n');
console.log('=' .repeat(60));

// Check Environment Variables
console.log('\n📋 Checking Environment Variables...\n');

const checks = {
  'AWS_REGION': process.env.AWS_REGION,
  'AWS_ACCESS_KEY_ID': process.env.AWS_ACCESS_KEY_ID ? '✓ Set' : '✗ Missing',
  'AWS_SECRET_ACCESS_KEY': process.env.AWS_SECRET_ACCESS_KEY ? '✓ Set' : '✗ Missing',
  'COGNITO_USER_POOL_ID': process.env.COGNITO_USER_POOL_ID,
  'COGNITO_CLIENT_ID': process.env.COGNITO_CLIENT_ID
};

let hasErrors = false;

Object.entries(checks).forEach(([key, value]) => {
  if (key === 'AWS_ACCESS_KEY_ID' || key === 'AWS_SECRET_ACCESS_KEY') {
    console.log(`  ${key}: ${value}`);
    if (value === '✗ Missing') hasErrors = true;
  } else {
    const status = value ? '✓' : '✗';
    const display = value || '(empty)';
    console.log(`  ${status} ${key}: ${display}`);
    if (!value) hasErrors = true;
  }
});

// Check Cognito Configuration
if (!process.env.COGNITO_USER_POOL_ID || !process.env.COGNITO_CLIENT_ID) {
  console.log('\n❌ COGNITO NOT CONFIGURED!');
  console.log('\n📝 To fix this, run:');
  console.log('   node setup-cognito.js');
  console.log('\n   This will create a Cognito User Pool and update your .env file.');
  process.exit(1);
}

// Test AWS Credentials
console.log('\n🔐 Testing AWS Credentials...\n');

AWS.config.update({ region: process.env.AWS_REGION || 'us-east-1' });
const cognito = new AWS.CognitoIdentityServiceProvider();

async function testCognitoConnection() {
  try {
    const params = {
      UserPoolId: process.env.COGNITO_USER_POOL_ID
    };
    
    const result = await cognito.describeUserPool(params).promise();
    
    console.log('  ✅ Successfully connected to Cognito User Pool');
    console.log(`  Pool Name: ${result.UserPool.Name}`);
    console.log(`  Status: ${result.UserPool.Status}`);
    console.log(`  Email Verification: ${result.UserPool.AutoVerifiedAttributes?.includes('email') ? 'Enabled' : 'Disabled'}`);
    
    // Check App Client
    console.log('\n🔐 Testing App Client Configuration...\n');
    
    const clientParams = {
      UserPoolId: process.env.COGNITO_USER_POOL_ID,
      ClientId: process.env.COGNITO_CLIENT_ID
    };
    
    const clientResult = await cognito.describeUserPoolClient(clientParams).promise();
    
    console.log('  ✅ App Client found');
    console.log(`  Client Name: ${clientResult.UserPoolClient.ClientName}`);
    
    // Check if USER_PASSWORD_AUTH is enabled
    const authFlows = clientResult.UserPoolClient.ExplicitAuthFlows || [];
    if (authFlows.includes('ALLOW_USER_PASSWORD_AUTH')) {
      console.log('  ✅ USER_PASSWORD_AUTH flow is enabled');
    } else {
      console.log('  ⚠️  USER_PASSWORD_AUTH flow is NOT enabled');
      console.log('     This is required for login to work!');
      hasErrors = true;
    }
    
    if (authFlows.includes('ALLOW_REFRESH_TOKEN_AUTH')) {
      console.log('  ✅ REFRESH_TOKEN_AUTH flow is enabled');
    }
    
    console.log('\n' + '='.repeat(60));
    
    if (hasErrors) {
      console.log('\n⚠️  Some issues were found. Please review the warnings above.');
    } else {
      console.log('\n✅ All checks passed! Your Cognito configuration looks good.');
      console.log('\n📝 Next Steps:');
      console.log('   1. Deploy your backend: serverless deploy');
      console.log('   2. Update your frontend API URL');
      console.log('   3. Test signup/login functionality');
    }
    
  } catch (error) {
    console.error('\n❌ Error connecting to Cognito:');
    console.error(`   Code: ${error.code}`);
    console.error(`   Message: ${error.message}`);
    
    if (error.code === 'ResourceNotFoundException') {
      console.log('\n💡 The User Pool ID or Client ID is incorrect or doesn\'t exist.');
      console.log('   Run: node setup-cognito.js');
    } else if (error.code === 'UnrecognizedClientException') {
      console.log('\n💡 The App Client ID is incorrect or doesn\'t belong to this User Pool.');
      console.log('   Run: node setup-cognito.js');
    } else if (error.code === 'InvalidParameterException') {
      console.log('\n💡 Invalid User Pool ID format.');
      console.log('   User Pool ID should be like: us-east-1_xxxxxxxxx');
    } else if (error.code === 'AccessDeniedException') {
      console.log('\n💡 AWS credentials don\'t have permission to access Cognito.');
      console.log('   Check your IAM permissions.');
    } else {
      console.log('\n💡 Please check your AWS credentials and Cognito configuration.');
    }
    
    process.exit(1);
  }
}

testCognitoConnection();
