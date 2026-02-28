// Make geoip-lite optional to reduce package size
let geoip;
try {
  geoip = require('geoip-lite');
} catch (e) {
  console.warn('geoip-lite not available, using fallback location detection');
  geoip = null;
}
const UAParser = require('ua-parser-js');

/**
 * Extract IP address from Lambda event
 */
const extractIPAddress = (event) => {
  // Try multiple sources for IP address
  return (
    event?.requestContext?.http?.sourceIp ||
    event?.requestContext?.identity?.sourceIp ||
    event?.headers?.['x-forwarded-for']?.split(',')[0] ||
    event?.headers?.['X-Forwarded-For']?.split(',')[0] ||
    'unknown'
  );
};

/**
 * Get geographic location from IP address
 */
const getIPLocation = (ip) => {
  if (!ip || ip === 'unknown') {
    return { country: 'unknown', region: 'unknown', city: 'unknown' };
  }
  
  // Use geoip-lite if available, otherwise return unknown
  if (!geoip) {
    console.log('GeoIP lookup skipped - geoip-lite not available');
    return { country: 'unknown', region: 'unknown', city: 'unknown' };
  }
  
  const geo = geoip.lookup(ip);
  if (!geo) {
    return { country: 'unknown', region: 'unknown', city: 'unknown' };
  }
  
  return {
    country: geo.country || 'unknown',
    region: geo.region || 'unknown',
    city: geo.city || 'unknown',
    timezone: geo.timezone || 'unknown',
  };
};

/**
 * Calculate distance between two locations (in km)
 * Simple Haversine formula implementation
 */
const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
};

/**
 * Extract device/browser fingerprint from User-Agent
 */
const getDeviceFingerprint = (event) => {
  const userAgent = 
    event?.headers?.['user-agent'] ||
    event?.headers?.['User-Agent'] ||
    'unknown';
  
  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  
  return {
    browser: `${result.browser.name || 'unknown'} ${result.browser.version || ''}`.trim(),
    os: `${result.os.name || 'unknown'} ${result.os.version || ''}`.trim(),
    device: result.device.type || 'desktop',
    deviceModel: result.device.model || 'unknown',
  };
};

/**
 * Check if location has changed significantly
 */
const isLocationSuspicious = (currentLocation, lastLocation, threshold = 500) => {
  if (!lastLocation || lastLocation.country === 'unknown') {
    return false; // First login or unknown previous location
  }
  
  // Different country is always suspicious
  if (currentLocation.country !== lastLocation.country) {
    return true;
  }
  
  // If we have coordinates, check distance
  if (currentLocation.lat && lastLocation.lat) {
    const distance = calculateDistance(
      currentLocation.lat,
      currentLocation.lon,
      lastLocation.lat,
      lastLocation.lon
    );
    
    return distance > threshold; // Suspicious if > threshold km
  }
  
  // Different region/city could be suspicious (but less so)
  return currentLocation.region !== lastLocation.region;
};

/**
 * Check if device has changed
 */
const isDeviceSuspicious = (currentDevice, lastDevice) => {
  if (!lastDevice || !lastDevice.browser) {
    return false; // First login
  }
  
  // Check if browser or OS changed completely
  const browserChanged = !currentDevice.browser.toLowerCase().includes(
    lastDevice.browser.toLowerCase().split(' ')[0]
  ) && !lastDevice.browser.toLowerCase().includes(
    currentDevice.browser.toLowerCase().split(' ')[0]
  );
  
  const osChanged = !currentDevice.os.toLowerCase().includes(
    lastDevice.os.toLowerCase().split(' ')[0]
  ) && !lastDevice.os.toLowerCase().includes(
    currentDevice.os.toLowerCase().split(' ')[0]
  );
  
  return browserChanged || osChanged;
};

/**
 * Check if login time pattern is unusual
 * Detects logins at unusual hours based on user's typical pattern
 */
const isTimeSuspicious = (loginHistory) => {
  if (!loginHistory || loginHistory.length < 3) {
    return false; // Not enough data to establish pattern
  }
  
  const currentHour = new Date().getHours();
  
  // Get typical login hours from history
  const loginHours = loginHistory.map(login => {
    const date = new Date(login.timestamp || login.lastLoginTime);
    return date.getHours();
  });
  
  // Calculate average login hour
  const avgHour = loginHours.reduce((a, b) => a + b, 0) / loginHours.length;
  
  // Check if current hour deviates significantly (more than 6 hours from average)
  const deviation = Math.abs(currentHour - avgHour);
  const normalizedDeviation = Math.min(deviation, 24 - deviation);
  
  return normalizedDeviation > 6;
};

/**
 * Rate limiting check - count login attempts in time window
 */
const checkRateLimit = (attempts, windowMinutes = 15, maxAttempts = 5) => {
  if (!attempts || attempts.length === 0) {
    return { limited: false, remainingAttempts: maxAttempts };
  }
  
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
  const recentAttempts = attempts.filter(
    timestamp => new Date(timestamp) > windowStart
  );
  
  const limited = recentAttempts.length >= maxAttempts;
  const remainingAttempts = Math.max(0, maxAttempts - recentAttempts.length);
  
  return { limited, remainingAttempts, recentAttempts: recentAttempts.length };
};

/**
 * Comprehensive cognitive check for login
 */
const performCognitiveCheck = (event, userProfile) => {
  const currentIP = extractIPAddress(event);
  const currentLocation = getIPLocation(currentIP);
  const currentDevice = getDeviceFingerprint(event);
  
  const checks = {
    locationSuspicious: false,
    deviceSuspicious: false,
    timeSuspicious: false,
    reasons: [],
  };
  
  // Check location
  if (userProfile.lastLoginIP && userProfile.lastLoginLocation) {
    checks.locationSuspicious = isLocationSuspicious(
      currentLocation,
      userProfile.lastLoginLocation
    );
    if (checks.locationSuspicious) {
      checks.reasons.push('Login from new location');
    }
  }
  
  // Check device
  if (userProfile.lastLoginDevice) {
    checks.deviceSuspicious = isDeviceSuspicious(
      currentDevice,
      userProfile.lastLoginDevice
    );
    if (checks.deviceSuspicious) {
      checks.reasons.push('Login from new device or browser');
    }
  }
  
  // Check time pattern
  if (userProfile.loginHistory && userProfile.loginHistory.length >= 3) {
    checks.timeSuspicious = isTimeSuspicious(userProfile.loginHistory);
    if (checks.timeSuspicious) {
      checks.reasons.push('Login at unusual time');
    }
  }
  
  checks.suspicious = checks.locationSuspicious || checks.deviceSuspicious || checks.timeSuspicious;
  checks.currentIP = currentIP;
  checks.currentLocation = currentLocation;
  checks.currentDevice = currentDevice;
  
  return checks;
};

module.exports = {
  extractIPAddress,
  getIPLocation,
  getDeviceFingerprint,
  isLocationSuspicious,
  isDeviceSuspicious,
  isTimeSuspicious,
  checkRateLimit,
  performCognitiveCheck,
};
