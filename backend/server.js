const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3005;

// Spotify cache for optimization
let spotifyCache = {
  lastTrackId: null,
  lastProgressMs: 0,
  lastFetchTime: 0,
  cachedData: null
};

// Trust Cloudflare proxy to get real client IP
app.set('trust proxy', true);

// Helper function to get real client IP through Cloudflare (IPv4 and IPv6)
function getClientIP(req) {
  const ip = req.headers['cf-connecting-ip'] ||      // Cloudflare real IP
             req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||  // First IP from proxy chain
             req.headers['x-real-ip'] ||             // nginx real IP
             req.connection.remoteAddress ||         // Direct connection
             req.socket.remoteAddress ||             // Socket connection
             req.ip ||                              // Express parsed IP
             'unknown';
             
  // Convert IPv6 mapped IPv4 to IPv4 format but keep original for logging
  if (ip && ip.startsWith('::ffff:')) {
    const ipv4 = ip.substring(7);
    console.log(`Client IP: ${ip} (mapped IPv4: ${ipv4})`);
    return ip; // Keep original format
  }
  
  // Log IPv6 addresses
  if (ip && ip.includes(':')) {
    console.log(`Client IP: ${ip} (IPv6)`);
  } else if (ip !== 'unknown') {
    console.log(`Client IP: ${ip} (IPv4)`);
  }
  
  return ip;
}

// Track database activity for connection renewal
function updateDbActivity() {
  dbLastActivity = Date.now();
  
  // Clear existing DB connection timer if any
  if (dbConnectionTimer) {
    clearTimeout(dbConnectionTimer);
    dbConnectionTimer = null;
  }
  
  // Set new DB connection renewal timer
  dbConnectionTimer = setTimeout(async () => {
    console.log('Database connection has been idle. Renewing connection...');
    try {
      if (db) {
        await db.end();
        db = null;
      }
      db = await createDbConnection();
      console.log('Database connection renewed successfully');
    } catch (error) {
      console.error('Failed to renew database connection:', error);
      db = null;
    }
  }, DB_INACTIVITY_THRESHOLD);
}

// Middleware to track database activity on all requests
function dbActivityTracker(req, res, next) {
  updateDbActivity();
  next();
}

app.use(dbActivityTracker);
app.use(cors({
  origin: [
    'http://localhost:3002', 
    'http://localhost:3003', 
    'http://127.0.0.1:3002',
    'http://127.0.0.1:3003', 
    'https://apibal.example.com', 
    'https://bal.example.com', 
    'https://lonya-spotfywebsearch-frontend.vercel.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept'],
  optionsSuccessStatus: 200,
  preflightContinue: false
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, 'background' + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

let db;
let spotifyToken = null;
let tokenExpiresAt = null;

// Global cache for searches
const searchCache = new Map();
const CACHE_DURATION = 60 * 60 * 1000; // 1 óra

// Database connection monitoring
let dbLastActivity = Date.now();
let dbConnectionTimer = null;
const DB_INACTIVITY_THRESHOLD = 30 * 60 * 1000; // 30 minutes before connection renewal

// Deezer API rate limiting
const deezerRateLimit = {
  requests: [],
  maxRequests: 45,
  timeWindow: 6000 // 5 seconds
};

// Device-based spam protection
const deviceActivity = new Map();
const SPAM_PROTECTION = {
  maxSearchesPerMinute: 15,
  cooldownPeriod: 4000 // 2 seconds between searches
};

// Spotify API rate limiting (rolling 30-second window)
const spotifyRateLimit = {
  requests: [],
  maxRequests: 50, // Conservative estimate - Spotify doesn't publish exact numbers
  timeWindow: 30000, // 30 seconds
  rateLimitedUntil: null, // Timestamp when rate limit expires
  consecutiveErrors: 0
};

async function createDbConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST ,
    user: process.env.DB_USER ,
    password: process.env.DB_PASSWORD  ,
    database: process.env.DB_NAME
  });
}

async function getDbConnection() {
  try {
    if (db) {
      // Test connection health
      try {
        await db.ping();
        return db;
      } catch (pingError) {
        console.log('Database connection lost, recreating...');
        db = null;
      }
    }
  } catch (error) {
    console.log('Database connection error, recreating...');
    db = null;
  }
  
  if (!db) {
    db = await createDbConnection();
    console.log('New database connection created');
  }
  return db;
}

async function initializeDatabase() {
  try {
    db = await createDbConnection();
    
    const createSubmissionsTable = `
      CREATE TABLE IF NOT EXISTS submissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        spotifyId VARCHAR(255) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        artist VARCHAR(255) NOT NULL,
        thumbnail TEXT,
        url TEXT NOT NULL,
        count INT DEFAULT 1,
        firstSubmittedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        lastSubmittedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        explicit BOOLEAN DEFAULT FALSE,
        platform VARCHAR(50) DEFAULT 'deezer'
      )
    `;
    
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('owner', 'admin') DEFAULT 'admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    const createUserLogsTable = `
      CREATE TABLE IF NOT EXISTS user_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50),
        action_type ENUM('login', 'logout', 'track_submit', 'admin_delete', 'admin_background_upload', 'admin_rating') NOT NULL,
        description TEXT,
        track_title VARCHAR(255) NULL,
        track_artist VARCHAR(255) NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        device_fingerprint VARCHAR(255),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_action_type (action_type),
        INDEX idx_created_at (created_at),
        INDEX idx_device_fingerprint (device_fingerprint)
      )
    `;

    const createDeviceSessionsTable = `
      CREATE TABLE IF NOT EXISTS device_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_fingerprint VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        search_count INT DEFAULT 0,
        last_search DATETIME,
        session_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_device_ip (device_fingerprint, ip_address),
        INDEX idx_device_fingerprint (device_fingerprint),
        INDEX idx_last_search (last_search)
      )
    `;

    const createSettingsTable = `
      CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT,
        description TEXT,
        updated_by VARCHAR(50),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_setting_key (setting_key)
      )
    `;

    const createAdminSpotifyTable = `
      CREATE TABLE IF NOT EXISTS admin_spotify (
        id INT AUTO_INCREMENT PRIMARY KEY,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at BIGINT NOT NULL,
        spotify_user_id VARCHAR(255),
        display_name VARCHAR(255),
        email VARCHAR(255),
        profile_image VARCHAR(500),
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    const fs = require('fs');
    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads');
    }
    
    await db.execute(createSubmissionsTable);
    
    // Add new columns if they don't exist
    try {
      await db.execute(`ALTER TABLE submissions ADD COLUMN explicit BOOLEAN DEFAULT FALSE`);
    } catch (e) {
      // Column already exists, ignore error
    }
    
    try {
      await db.execute(`ALTER TABLE submissions ADD COLUMN platform VARCHAR(50) DEFAULT 'deezer'`);
    } catch (e) {
      // Column already exists, ignore error
    }
    
    try {
      await db.execute(`ALTER TABLE submissions ADD COLUMN rating ENUM('ok', 'bad', 'middle') DEFAULT NULL`);
    } catch (e) {
      // Column already exists, ignore error
    }
    
    await db.execute(createUsersTable);
    await db.execute(createUserLogsTable);
    await db.execute(createDeviceSessionsTable);
    await db.execute(createSettingsTable);
    await db.execute(createAdminSpotifyTable);
    
    // Check if password column exists, if not, add it
    try {
      await db.execute('SELECT password FROM users LIMIT 1');
    } catch (error) {
      if (error.code === 'ER_BAD_FIELD_ERROR') {
        // Add password column if it doesn't exist
        await db.execute('ALTER TABLE users ADD COLUMN password VARCHAR(255) NOT NULL DEFAULT ""');
        console.log('Added password column to users table');
      }
    }
    
    // Insert or update default users
    const matePasswordHash = await bcrypt.hash(process.env.MATE_PASSWORD || 'mate123', 10);
    const dokPasswordHash = await bcrypt.hash(process.env.DOK_PASSWORD || 'dok123', 10);
    
    // Check if users exist and update their passwords, or insert new ones
    const [existingMate] = await db.execute('SELECT * FROM users WHERE username = ?', ['mate']);
    if (existingMate.length > 0) {
      await db.execute('UPDATE users SET password = ?, role = ? WHERE username = ?', [matePasswordHash, 'owner', 'mate']);
    } else {
      await db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ['mate', matePasswordHash, 'owner']);
    }
    
    const [existingDok] = await db.execute('SELECT * FROM users WHERE username = ?', ['dök']);
    if (existingDok.length > 0) {
      await db.execute('UPDATE users SET password = ?, role = ? WHERE username = ?', [dokPasswordHash, 'admin', 'dök']);
    } else {
      await db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ['dök', dokPasswordHash, 'admin']);
    }
    
    // Check if settings table has the correct structure, if not, recreate it
    try {
      await db.execute('SELECT setting_key FROM settings LIMIT 1');
    } catch (error) {
      if (error.code === 'ER_BAD_FIELD_ERROR') {
        console.log('Settings table has incorrect structure, recreating...');
        await db.execute('DROP TABLE IF EXISTS settings');
        await db.execute(createSettingsTable);
        console.log('Settings table recreated with correct structure');
      }
    }
    
    // Initialize default settings
    const defaultSettings = [
      {
        key: 'search_page_visible',
        value: 'true',
        description: 'Controls whether the search page is visible to users'
      },
      {
        key: 'search_functionality_enabled',
        value: 'true',
        description: 'Controls whether users can perform searches'
      },
      {
        key: 'track_submission_enabled',
        value: 'true',
        description: 'Controls whether users can submit tracks'
      },
      {
        key: 'maintenance_message',
        value: '',
        description: 'Custom message to display when functionality is disabled'
      },
      {
        key: 'site_mode',
        value: 'normal',
        description: 'Site operation mode: normal, maintenance, or playlist'
      },
      {
        key: 'preferred_search_api',
        value: 'auto',
        description: 'Preferred search API: auto (Spotify with Deezer fallback), spotify (Spotify only), deezer (Deezer only)'
      },
      {
        key: 'spotify_api_enabled',
        value: 'true',
        description: 'Controls whether Spotify API can be used for searches'
      }
    ];
    
    for (const setting of defaultSettings) {
      const [existing] = await db.execute('SELECT * FROM settings WHERE setting_key = ?', [setting.key]);
      if (existing.length === 0) {
        await db.execute(
          'INSERT INTO settings (setting_key, setting_value, description, updated_by) VALUES (?, ?, ?, ?)',
          [setting.key, setting.value, setting.description, 'system']
        );
      }
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

async function getSpotifyToken() {
  if (spotifyToken && tokenExpiresAt && Date.now() < tokenExpiresAt) {
    return spotifyToken;
  }

  try {
    const response = await axios.post('https://accounts.spotify.com/api/token', 
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    spotifyToken = response.data.access_token;
    tokenExpiresAt = Date.now() + (response.data.expires_in * 1000);
    return spotifyToken;
  } catch (error) {
    console.error('Error getting Spotify token:', error);
    throw error;
  }
}

// Spotify rate limiting functions
function isSpotifyRateLimited() {
  const now = Date.now();
  
  // Check if we're in a manual rate limit period
  if (spotifyRateLimit.rateLimitedUntil && now < spotifyRateLimit.rateLimitedUntil) {
    return true;
  }
  
  // Clean old requests (older than timeWindow)
  spotifyRateLimit.requests = spotifyRateLimit.requests.filter(
    timestamp => now - timestamp < spotifyRateLimit.timeWindow
  );
  
  // Check if we're approaching the limit
  return spotifyRateLimit.requests.length >= spotifyRateLimit.maxRequests;
}

function recordSpotifyRequest() {
  spotifyRateLimit.requests.push(Date.now());
}

function handleSpotifyRateLimit(retryAfter = null) {
  const now = Date.now();
  
  // If Spotify provides a Retry-After header, use it
  if (retryAfter) {
    spotifyRateLimit.rateLimitedUntil = now + (retryAfter * 1000);
    console.log(`⏰ Spotify rate limit cooldown set for ${retryAfter} seconds`);
    console.log(`   Cooldown until: ${new Date(spotifyRateLimit.rateLimitedUntil).toLocaleString()}`);
  } else {
    // Default 30-second cooldown
    spotifyRateLimit.rateLimitedUntil = now + 30000;
    console.log(`⏰ Spotify rate limit default cooldown: 30 seconds`);
    console.log(`   Cooldown until: ${new Date(spotifyRateLimit.rateLimitedUntil).toLocaleString()}`);
  }
  
  spotifyRateLimit.consecutiveErrors++;
  console.log(`📊 Spotify API Stats:`);
  console.log(`   Consecutive errors: ${spotifyRateLimit.consecutiveErrors}`);
  console.log(`   Current requests in window: ${spotifyRateLimit.requests.length}/${spotifyRateLimit.maxRequests}`);
  console.log(`   Switching to Deezer fallback for subsequent searches`);
}

function resetSpotifyErrorCount() {
  spotifyRateLimit.consecutiveErrors = 0;
}

async function getSettingsValue(key, defaultValue = '') {
  try {
    const connection = await getDbConnection();
    const [rows] = await connection.execute('SELECT setting_value FROM settings WHERE setting_key = ?', [key]);
    return rows.length > 0 ? rows[0].setting_value : defaultValue;
  } catch (error) {
    console.error(`Error getting setting ${key}:`, error);
    return defaultValue;
  }
}

async function searchDeezer(query) {
  try {
    console.log(`Deezer API request for query: "${query}"`);
    const response = await axios.get('https://api.deezer.com/search', {
      params: {
        q: query,
        limit: 10
      }
    });

    const trackCount = response.data.data.length;
    console.log(`Deezer API successful: ${trackCount} tracks found for query: "${query}"`);

    return response.data.data.map(track => ({
      id: track.id.toString(),
      title: track.title,
      artist: track.artist.name,
      thumbnail: track.album.cover_medium || track.album.cover || '',
      url: track.link,
      explicit: track.explicit_lyrics || false,
      preview_url: track.preview,
      platform: 'deezer'
    }));
  } catch (error) {
    console.error(`Deezer search error for query "${query}":`, error.message);
    return null;
  }
}

async function searchSpotify(query) {
  // Check if Spotify is rate limited
  if (isSpotifyRateLimited()) {
    const rateLimitedUntil = spotifyRateLimit.rateLimitedUntil ? new Date(spotifyRateLimit.rateLimitedUntil).toLocaleTimeString() : 'N/A';
    console.log(`🔒 Spotify API currently rate limited - skipping request`);
    console.log(`   Query: "${query}"`);
    console.log(`   Current requests: ${spotifyRateLimit.requests.length}/${spotifyRateLimit.maxRequests}`);
    console.log(`   Rate limit expires at: ${rateLimitedUntil}`);
    console.log(`   🔄 Will try Deezer instead`);
    return null;
  }

  try {
    const token = await getSpotifyToken();
    
    // Record the request for rate limiting
    recordSpotifyRequest();
    console.log(`Spotify API request (${spotifyRateLimit.requests.length}/${spotifyRateLimit.maxRequests}) for query: "${query}"`);
    
    const response = await axios.get('https://api.spotify.com/v1/search', {
      params: {
        q: query,
        type: 'track',
        limit: 10
      },
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    // Reset error count on successful request
    resetSpotifyErrorCount();
    const trackCount = response.data.tracks.items.length;
    console.log(`Spotify API successful: ${trackCount} tracks found for query: "${query}"`);

    return response.data.tracks.items.map(track => ({
      id: track.id,
      title: track.name,
      artist: track.artists.map(artist => artist.name).join(', '),
      thumbnail: track.album.images[0]?.url || '',
      url: track.external_urls.spotify,
      explicit: track.explicit || false,
      preview_url: track.preview_url,
      platform: 'spotify'
    }));
  } catch (error) {
    console.error(`Spotify search error for query "${query}":`, error.message);
    
    // Handle rate limit specifically
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      console.log(`🚫 SPOTIFY RATE LIMIT HIT!`);
      console.log(`   Query: "${query}"`);
      console.log(`   Status Code: 429`);
      console.log(`   Retry-After Header: ${retryAfter || 'Not provided'} seconds`);
      console.log(`   Current Requests: ${spotifyRateLimit.requests.length}/${spotifyRateLimit.maxRequests}`);
      console.log(`   Error Message: ${error.response.data?.error?.message || 'No specific error message'}`);
      handleSpotifyRateLimit(retryAfter);
    } else if (error.response) {
      console.log(`❌ Spotify API Error ${error.response.status}: ${error.response.data?.error?.message || error.message}`);
    } else {
      console.log(`❌ Spotify Network Error: ${error.message}`);
    }
    
    return null;
  }
}

app.get('/api/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 3) {
      return res.status(400).json({ error: 'Query must be at least 3 characters long' });
    }

    // Get current API preferences from settings
    const preferredApi = await getSettingsValue('preferred_search_api', 'auto');
    const spotifyEnabled = await getSettingsValue('spotify_api_enabled', 'true') === 'true';
    
    let tracks = [];
    let searchLog = [];

    // Determine search strategy
    if (preferredApi === 'deezer') {
      // Deezer only
      searchLog.push('Using Deezer API (admin preference)');
      tracks = await searchDeezer(q);
      if (!tracks) {
        searchLog.push('Deezer search failed');
        return res.status(500).json({ error: 'Deezer search failed', searchLog });
      }
    } else if (preferredApi === 'spotify' && spotifyEnabled) {
      // Spotify only
      searchLog.push('Using Spotify API (admin preference)');
      tracks = await searchSpotify(q);
      if (!tracks) {
        searchLog.push('Spotify search failed or rate limited');
        return res.status(500).json({ error: 'Spotify search failed', searchLog });
      }
    } else {
      // Auto mode (default) - Try Spotify first, fallback to Deezer
      if (spotifyEnabled && !isSpotifyRateLimited()) {
        searchLog.push('Trying Spotify API first (auto mode)');
        tracks = await searchSpotify(q);
        
        if (tracks && tracks.length > 0) {
          searchLog.push(`Spotify API successful: ${tracks.length} tracks found`);
        } else {
          searchLog.push('Spotify API failed or returned no results, trying Deezer fallback');
          tracks = await searchDeezer(q);
          if (tracks && tracks.length > 0) {
            searchLog.push(`Deezer fallback successful: ${tracks.length} tracks found`);
          }
        }
      } else {
        if (!spotifyEnabled) {
          searchLog.push('Spotify API disabled, using Deezer');
        } else {
          searchLog.push('Spotify API rate limited, using Deezer fallback');
        }
        tracks = await searchDeezer(q);
        if (tracks && tracks.length > 0) {
          searchLog.push(`Deezer API successful: ${tracks.length} tracks found`);
        }
      }
    }

    if (!tracks || tracks.length === 0) {
      searchLog.push('All APIs failed or returned no results');
      console.log(`Search failed for query "${q}": ${searchLog.join('; ')}`);
      return res.status(500).json({ 
        error: 'All search APIs failed or returned no results',
        searchLog: searchLog
      });
    }

    // Log successful search
    const platforms = [...new Set(tracks.map(t => t.platform))];
    console.log(`Search successful for query "${q}": ${tracks.length} tracks from ${platforms.join(', ')} (Strategy: ${preferredApi})`);
    
    // Add metadata about the search
    const response = {
      tracks,
      metadata: {
        query: q,
        searchStrategy: preferredApi,
        spotifyEnabled,
        totalResults: tracks.length,
        platforms: platforms,
        searchLog: process.env.NODE_ENV === 'development' ? searchLog : undefined
      }
    };

    // For backward compatibility, send just tracks array if client expects it
    res.json(tracks);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

app.post('/api/submit', async (req, res) => {
  try {
    const { id, title, artist, thumbnail, url, username, explicit, platform } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');

    if (!id || !title || !artist || !url) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const connection = await getDbConnection();
    const [existing] = await connection.execute(
      'SELECT * FROM submissions WHERE spotifyId = ?',
      [id]
    );

    if (existing.length > 0) {
      // Update existing track - csak a count és időbélyeg frissítése, explicit és platform nem
      await connection.execute(
        'UPDATE submissions SET count = count + 1, lastSubmittedAt = CURRENT_TIMESTAMP WHERE spotifyId = ?',
        [id]
      );
    } else {
      await connection.execute(
        'INSERT INTO submissions (spotifyId, title, artist, thumbnail, url, explicit, platform) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [id, title, artist, thumbnail, url, explicit || false, platform || 'deezer']
      );
    }

    // Log the track submission
    await logUserAction(
      username || 'anonymous', 
      'track_submit', 
      `Submitted track: ${title}`, 
      title, 
      artist, 
      clientIP, 
      userAgent
    );

    res.json({ success: true, message: 'Track submitted successfully' });
  } catch (error) {
    console.error('Submit error:', error);
    res.status(500).json({ error: 'Submit failed' });
  }
});

const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000;

async function logUserAction(username, actionType, description = '', trackTitle = null, trackArtist = null, ipAddress = null, userAgent = null) {
  try {
    const connection = await getDbConnection();
    await connection.execute(
      `INSERT INTO user_logs (username, action_type, description, track_title, track_artist, ip_address, user_agent) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [username, actionType, description, trackTitle, trackArtist, ipAddress, userAgent]
    );
  } catch (error) {
    console.error('Logging error:', error);
  }
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (!loginAttempts.has(clientIP)) {
      loginAttempts.set(clientIP, { attempts: 0, lastAttempt: 0 });
    }
    
    const userAttempts = loginAttempts.get(clientIP);
    const now = Date.now();
    
    if (userAttempts.attempts >= MAX_LOGIN_ATTEMPTS && 
        (now - userAttempts.lastAttempt) < LOCKOUT_TIME) {
      return res.status(429).json({ 
        error: 'Too many login attempts. Try again in 15 minutes.' 
      });
    }
    
    if ((now - userAttempts.lastAttempt) > LOCKOUT_TIME) {
      userAttempts.attempts = 0;
    }
    
    // Check if user exists
    const connection = await getDbConnection();
    const [users] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      await logUserAction(username, 'login', `Failed login attempt - user not found`, null, null, clientIP, userAgent);
      userAttempts.attempts++;
      userAttempts.lastAttempt = now;
      loginAttempts.set(clientIP, userAttempts);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    
    // Check if user has a password set
    if (!user.password || user.password === '') {
      await logUserAction(username, 'login', `Failed login attempt - no password set for user`, null, null, clientIP, userAgent);
      return res.status(401).json({ error: 'User has no password set. Please contact administrator.' });
    }
    
    // Check password against user's stored hash
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (passwordMatch) {
      userAttempts.attempts = 0;
      
      await logUserAction(username, 'login', `Successful login`, null, null, clientIP, userAgent);
      
      res.json({ success: true, user: { username: user.username, role: user.role } });
    } else {
      await logUserAction(username, 'login', `Failed login attempt - wrong password`, null, null, clientIP, userAgent);
      userAttempts.attempts++;
      userAttempts.lastAttempt = now;
      loginAttempts.set(clientIP, userAttempts);
      
      const attemptsLeft = MAX_LOGIN_ATTEMPTS - userAttempts.attempts;
      res.status(401).json({ 
        error: `Invalid password. ${attemptsLeft} attempts remaining.` 
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

async function authenticateAdmin(req, res, next) {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(401).json({ error: 'Username and password required for each admin request' });
    }
    
    const connection = await getDbConnection();
    const [users] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    
    if (!user.password || user.password === '') {
      return res.status(401).json({ error: 'User has no password set' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.adminUser = {
      username: user.username,
      role: user.role
    };
    
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
}

function requireOwner(req, res, next) {
  if (req.adminUser.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required' });
  }
  next();
}

// IP-based rate limiting removed

app.post('/api/admin/submissions', authenticateAdmin, async (req, res) => {
  try {
    // Just get all submissions without any sorting - frontend will handle sorting
    try {
      const [submissions] = await db.execute(
        `SELECT * FROM submissions`
      );
      res.json(submissions);
    } catch (dbError) {
      console.log('Database error, trying to reconnect...');
      db = await createDbConnection();
      const [submissions] = await db.execute(
        `SELECT * FROM submissions`
      );
      res.json(submissions);
    }
  } catch (error) {
    console.error('Get submissions error:', error);
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

app.delete('/api/admin/submission/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    // Get track info before deletion for logging
    const connection = await getDbConnection();
    const [trackInfo] = await connection.execute('SELECT title, artist FROM submissions WHERE id = ?', [id]);
    const track = trackInfo[0];
    
    await connection.execute('DELETE FROM submissions WHERE id = ?', [id]);
    
    // Log the deletion
    if (track) {
      await logUserAction(
        req.adminUser.username,
        'admin_delete',
        `Deleted track: ${track.title}`,
        track.title,
        track.artist,
        clientIP,
        userAgent
      );
    }
    
    res.json({ success: true, message: 'Submission deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.put('/api/admin/submission/:id/rating', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    // Validate rating value
    const validRatings = ['ok', 'bad', 'middle', null];
    if (rating !== null && !validRatings.includes(rating)) {
      return res.status(400).json({ error: 'Invalid rating value. Must be ok, bad, middle, or null' });
    }
    
    // Get track info for logging
    const connection = await getDbConnection();
    const [trackInfo] = await connection.execute('SELECT title, artist FROM submissions WHERE id = ?', [id]);
    const track = trackInfo[0];
    
    if (!track) {
      return res.status(404).json({ error: 'Submission not found' });
    }
    
    // Update rating without touching lastSubmittedAt
    await connection.execute('UPDATE submissions SET rating = ?, lastSubmittedAt = lastSubmittedAt WHERE id = ?', [rating, id]);
    
    // Log the rating action
    const ratingText = rating ? rating.toUpperCase() : 'CLEARED';
    await logUserAction(
      req.adminUser.username,
      'admin_rating',
      `Rated track as ${ratingText}: ${track.title}`,
      track.title,
      track.artist,
      clientIP,
      userAgent
    );
    
    res.json({ success: true, message: 'Rating updated successfully', rating });
  } catch (error) {
    console.error('Rating update error:', error);
    res.status(500).json({ error: 'Rating update failed' });
  }
});

// Get user logs - only for owner (mate)
app.post('/api/admin/logs', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const { page = 1, limit = 50, action_type, username } = req.query;
    const offset = (page - 1) * limit;
    
    let whereClause = 'WHERE 1=1';
    let params = [];
    
    if (action_type) {
      whereClause += ' AND action_type = ?';
      params.push(action_type);
    }
    
    if (username) {
      whereClause += ' AND username = ?';
      params.push(username);
    }
    
    const connection = await getDbConnection();
    const [logs] = await connection.execute(
      `SELECT * FROM user_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), parseInt(offset)]
    );
    
    const [countResult] = await connection.execute(
      `SELECT COUNT(*) as total FROM user_logs ${whereClause}`,
      params
    );
    
    res.json({
      logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Get logs error:', error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// Change user password - only for owner
app.post('/api/admin/change-password', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const { targetUsername, newPassword } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    if (!targetUsername || !newPassword) {
      return res.status(400).json({ error: 'Username and new password are required' });
    }
    
    // Check if target user exists
    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [targetUsername]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    
    // Update password
    await connection.execute(
      'UPDATE users SET password = ? WHERE username = ?',
      [passwordHash, targetUsername]
    );
    
    // Log the password change
    await logUserAction(
      req.adminUser.username,
      'admin_password_change',
      `Changed password for user: ${targetUsername}`,
      null,
      null,
      clientIP,
      userAgent
    );
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Get all users - only for owner
app.post('/api/admin/users/list', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const connection = await getDbConnection();
    const [users] = await connection.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at ASC');
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Create new user - only for owner (can only create admin users)
app.post('/api/admin/users', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    // Use newUsername and newPassword to avoid conflicts with admin auth fields
    const { newUsername, newPassword } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    if (!newUsername || !newPassword) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (newUsername.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters long' });
    }
    
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters long' });
    }
    
    // Check if username already exists
    const connection = await getDbConnection();
    const [existingUsers] = await connection.execute('SELECT * FROM users WHERE username = ?', [newUsername]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    
    // Insert new user (only admin role allowed)
    await connection.execute(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [newUsername, passwordHash, 'admin']
    );
    
    // Log the user creation
    await logUserAction(
      req.adminUser.username,
      'admin_user_create',
      `Created new admin user: ${newUsername}`,
      null,
      null,
      clientIP,
      userAgent
    );
    
    res.json({ success: true, message: 'User created successfully' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Delete user - only for owner (cannot delete owner users)
app.delete('/api/admin/users/:username', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const { username } = req.params;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    // Check if user exists
    const connection = await getDbConnection();
    const [users] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = users[0];
    
    // Cannot delete owner users
    if (user.role === 'owner') {
      return res.status(403).json({ error: 'Cannot delete owner users' });
    }
    
    // Cannot delete yourself
    if (username === req.adminUser.username) {
      return res.status(403).json({ error: 'Cannot delete your own account' });
    }
    
    // Delete user
    await connection.execute('DELETE FROM users WHERE username = ?', [username]);
    
    // Log the user deletion
    await logUserAction(
      req.adminUser.username,
      'admin_user_delete',
      `Deleted user: ${username}`,
      null,
      null,
      clientIP,
      userAgent
    );
    
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Rename user - only for owner (cannot rename owner users)
app.put('/api/admin/users/:username/rename', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const { username } = req.params;
    const { newUsername } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    if (!newUsername) {
      return res.status(400).json({ error: 'New username is required' });
    }
    
    if (newUsername.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters long' });
    }
    
    // Check if original user exists
    const connection = await getDbConnection();
    const [users] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = users[0];
    
    // Cannot rename owner users
    if (user.role === 'owner') {
      return res.status(403).json({ error: 'Cannot rename owner users' });
    }
    
    // Check if new username already exists
    const [existingUsers] = await db.execute('SELECT * FROM users WHERE username = ?', [newUsername]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'New username already exists' });
    }
    
    // Update username
    await connection.execute('UPDATE users SET username = ? WHERE username = ?', [newUsername, username]);
    
    // Log the username change
    await logUserAction(
      req.adminUser.username,
      'admin_user_rename',
      `Renamed user from ${username} to ${newUsername}`,
      null,
      null,
      clientIP,
      userAgent
    );
    
    res.json({ success: true, message: 'Username changed successfully' });
  } catch (error) {
    console.error('Rename user error:', error);
    res.status(500).json({ error: 'Failed to rename user' });
  }
});

// Get settings - public endpoint for basic settings
app.get('/api/settings', async (req, res) => {
  try {
    const connection = await getDbConnection();
    const [settings] = await connection.execute(
      'SELECT setting_key, setting_value FROM settings WHERE setting_key IN (?, ?)',
      ['site_mode', 'maintenance_message']
    );
    
    const settingsObj = {};
    settings.forEach(setting => {
      settingsObj[setting.setting_key] = setting.setting_value;
    });
    
    res.json(settingsObj);
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Get all settings - admin endpoint (owner only)
app.post('/api/admin/settings', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const connection = await getDbConnection();
    const [settings] = await connection.execute(
      'SELECT * FROM settings ORDER BY setting_key ASC'
    );
    res.json(settings);
  } catch (error) {
    console.error('Get admin settings error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Update settings - admin endpoint (owner only)
app.put('/api/admin/settings', authenticateAdmin, requireOwner, async (req, res) => {
  try {
    const { settings } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');
    
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Settings object is required' });
    }
    
    const connection = await getDbConnection();
    const updatedSettings = [];
    
    // Update each setting
    for (const [key, value] of Object.entries(settings)) {
      // Validate setting key exists
      const [existing] = await connection.execute('SELECT * FROM settings WHERE setting_key = ?', [key]);
      if (existing.length > 0) {
        await connection.execute(
          'UPDATE settings SET setting_value = ?, updated_by = ? WHERE setting_key = ?',
          [String(value), req.adminUser.username, key]
        );
        updatedSettings.push({ key, value });
      }
    }
    
    // Log the settings change
    await logUserAction(
      req.adminUser.username,
      'admin_settings_update',
      `Updated settings: ${updatedSettings.map(s => s.key).join(', ')}`,
      null,
      null,
      clientIP,
      userAgent
    );
    
    res.json({ 
      success: true, 
      message: 'Settings updated successfully',
      updatedSettings 
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Spotify OAuth endpoints for playlist management
app.get('/api/spotify/auth', (req, res) => {
  const scopes = 'playlist-modify-public playlist-modify-private user-read-private user-read-email';
  const redirectUri = 'https://apibal.example.com/api/spotify/callback';
  
  const spotifyAuthUrl = `https://accounts.spotify.com/authorize?` +
    `client_id=${process.env.SPOTIFY_CLIENT_ID}&` +
    `response_type=code&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `scope=${encodeURIComponent(scopes)}`;
  
  res.redirect(spotifyAuthUrl);
});

// Admin Spotify OAuth endpoints for "What's Playing" feature
app.get('/api/admin/spotify/connect', (req, res) => {
  const scopes = 'user-read-currently-playing user-read-playback-state user-read-private user-read-email';
  const redirectUri = 'https://apibal.example.com/api/admin/spotify/callback';
  
  const spotifyAuthUrl = `https://accounts.spotify.com/authorize?` +
    `client_id=${process.env.SPOTIFY_CLIENT_ID}&` +
    `response_type=code&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `scope=${encodeURIComponent(scopes)}`;
  
  res.redirect(spotifyAuthUrl);
});

app.get('/api/spotify/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.redirect('https://bal.example.com/admin?spotify_error=no_code');
    }
    
    const redirectUri = 'https://apibal.example.com/api/spotify/callback';
    
    // Exchange code for access token
    const tokenResponse = await axios.post('https://accounts.spotify.com/api/token', 
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        client_id: process.env.SPOTIFY_CLIENT_ID,
        client_secret: process.env.SPOTIFY_CLIENT_SECRET
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    
    // Get user info
    const userResponse = await axios.get('https://api.spotify.com/v1/me', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });
    
    const userData = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      user: {
        id: userResponse.data.id,
        display_name: userResponse.data.display_name,
        email: userResponse.data.email
      }
    };
    
    // Redirect back to admin with token data
    const dataParam = encodeURIComponent(JSON.stringify(userData));
    res.redirect(`https://bal.example.com/admin?spotify_success=${dataParam}`);
    
  } catch (error) {
    console.error('Spotify OAuth error:', error);
    res.redirect('https://bal.example.com/admin?spotify_error=auth_failed');
  }
});

app.get('/api/admin/spotify/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.redirect('https://bal.example.com/admin?admin_spotify_error=no_code');
    }
    
    const redirectUri = 'https://apibal.example.com/api/admin/spotify/callback';
    
    // Exchange code for access token
    const tokenResponse = await axios.post('https://accounts.spotify.com/api/token', 
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        client_id: process.env.SPOTIFY_CLIENT_ID,
        client_secret: process.env.SPOTIFY_CLIENT_SECRET
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    
    // Get user info
    const userResponse = await axios.get('https://api.spotify.com/v1/me', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });
    
    // Store in database
    const connection = await getDbConnection();
    await connection.execute(
      'DELETE FROM admin_spotify'  // Only one admin connection at a time
    );
    
    await connection.execute(
      'INSERT INTO admin_spotify (access_token, refresh_token, expires_at, spotify_user_id, display_name, email, profile_image) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        access_token,
        refresh_token,
        Date.now() + (expires_in * 1000),
        userResponse.data.id,
        userResponse.data.display_name,
        userResponse.data.email,
        userResponse.data.images?.[0]?.url || ''
      ]
    );
    
    res.redirect('https://bal.example.com/admin?admin_spotify_success=connected');
    
  } catch (error) {
    console.error('Admin Spotify OAuth error:', error);
    res.redirect('https://bal.example.com/admin?admin_spotify_error=auth_failed');
  }
});

// Add track to Spotify playlist
app.post('/api/admin/add-to-spotify-playlist', authenticateAdmin, async (req, res) => {
  try {
    const { trackTitle, trackArtist, spotifyAccessToken } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent');

    if (!trackTitle || !trackArtist) {
      return res.status(400).json({ error: 'Track title and artist are required' });
    }

    if (!spotifyAccessToken) {
      return res.status(400).json({ error: 'Spotify access token is required' });
    }

    // Search for the track on Spotify using user's token
    const searchQuery = `track:"${trackTitle}" artist:"${trackArtist}"`;
    
    const searchResponse = await axios.get('https://api.spotify.com/v1/search', {
      params: {
        q: searchQuery,
        type: 'track',
        limit: 1
      },
      headers: {
        'Authorization': `Bearer ${spotifyAccessToken}`
      }
    });

    if (!searchResponse.data.tracks.items.length) {
      return res.status(404).json({ error: 'Track not found on Spotify' });
    }

    const spotifyTrack = searchResponse.data.tracks.items[0];
    const spotifyTrackUri = spotifyTrack.uri;

    // Add track to the specified Spotify playlist
    const playlistId = '2Hkj2Y2LWrTZmPtkSz6MMZ'; // The playlist ID from the URL

    await axios.post(`https://api.spotify.com/v1/playlists/${playlistId}/tracks`, {
      uris: [spotifyTrackUri]
    }, {
      headers: {
        'Authorization': `Bearer ${spotifyAccessToken}`,
        'Content-Type': 'application/json'
      }
    });

    // Log the action
    await logUserAction(
      req.adminUser.username,
      'admin_spotify_add',
      `Added track to Spotify playlist: ${trackTitle}`,
      trackTitle,
      trackArtist,
      clientIP,
      userAgent
    );

    res.json({ 
      success: true, 
      message: 'Track successfully added to Spotify playlist',
      spotifyTrack: {
        name: spotifyTrack.name,
        artist: spotifyTrack.artists.map(a => a.name).join(', '),
        url: spotifyTrack.external_urls.spotify
      }
    });
  } catch (error) {
    console.error('Spotify playlist add error:', error);
    
    if (error.response?.status === 401) {
      return res.status(401).json({ error: 'Spotify authentication failed - please login again' });
    }
    
    if (error.response?.status === 403) {
      return res.status(403).json({ error: 'No permission to modify this Spotify playlist' });
    }
    
    const errorMessage = error.response?.data?.error?.message || 'Failed to add track to Spotify playlist';
    res.status(500).json({ error: errorMessage });
  }
});

// Get currently playing track from admin's Spotify (public endpoint)
app.get('/api/spotify/whats-playing', async (req, res) => {
  try {
    const connection = await getDbConnection();
    const [adminSpotify] = await connection.execute('SELECT * FROM admin_spotify ORDER BY created_at DESC LIMIT 1');
    
    if (!adminSpotify.length) {
      return res.json({ 
        isPlaying: false, 
        message: 'Admin nincs csatlakoztatva Spotify-hoz' 
      });
    }
    
    const admin = adminSpotify[0];
    
    // Check if token is expired
    if (Date.now() >= admin.expires_at) {
      return res.json({ 
        isPlaying: false, 
        message: 'Spotify kapcsolat lejárt' 
      });
    }
    
    const now = Date.now();
    const timeSinceLastFetch = now - spotifyCache.lastFetchTime;
    
    // Only fetch from Spotify API if enough time has passed or we need fresh data
    let shouldFetch = timeSinceLastFetch > 15000; // At least 15 seconds between calls
    
    if (!shouldFetch && spotifyCache.cachedData && spotifyCache.lastTrackId) {
      // Return cached data with updated progress if same track
      const estimatedProgress = spotifyCache.lastProgressMs + timeSinceLastFetch;
      const updatedData = {
        ...spotifyCache.cachedData,
        progress_ms: Math.min(estimatedProgress, spotifyCache.cachedData.duration_ms),
        timestamp: now
      };
      return res.json(updatedData);
    }
    
    // Get currently playing track from Spotify API
    const response = await axios.get('https://api.spotify.com/v1/me/player/currently-playing', {
      headers: {
        'Authorization': `Bearer ${admin.access_token}`
      }
    });
    
    if (response.status === 204 || !response.data || !response.data.item) {
      // Clear cache when nothing is playing
      spotifyCache = {
        lastTrackId: null,
        lastProgressMs: 0,
        lastFetchTime: now,
        cachedData: null
      };
      
      return res.json({ 
        isPlaying: false, 
        message: 'Jelenleg nem hallgatok semmit',
        adminUser: {
          name: admin.display_name,
          image: admin.profile_image
        }
      });
    }
    
    const track = response.data.item;
    const currentlyPlaying = {
      isPlaying: response.data.is_playing,
      id: track.id,
      name: track.name,
      artist: track.artists.map(a => a.name).join(', '),
      album: track.album.name,
      image: track.album.images[0]?.url || '',
      url: track.external_urls.spotify,
      progress_ms: response.data.progress_ms,
      duration_ms: track.duration_ms,
      device: response.data.device?.name || null,
      // Additional track info
      explicit: track.explicit,
      popularity: track.popularity,
      release_date: track.album.release_date,
      album_type: track.album.album_type,
      // Playback info
      shuffle_state: response.data.shuffle_state,
      repeat_state: response.data.repeat_state,
      timestamp: response.data.timestamp,
      // Context info
      context: response.data.context ? {
        type: response.data.context.type,
        name: response.data.context.type === 'playlist' ? 'Playlist' : 
              response.data.context.type === 'album' ? track.album.name :
              response.data.context.type === 'artist' ? track.artists[0].name : 'Context'
      } : null,
      adminUser: {
        name: admin.display_name,
        image: admin.profile_image
      }
    };
    
    // Update cache
    spotifyCache = {
      lastTrackId: track.id,
      lastProgressMs: response.data.progress_ms,
      lastFetchTime: now,
      cachedData: currentlyPlaying
    };
    
    res.json(currentlyPlaying);
  } catch (error) {
    console.error('Currently playing fetch error:', error);
    res.json({ 
      isPlaying: false, 
      message: 'Hiba történt a lekérdezés során',
      error: true 
    });
  }
});

// Get admin Spotify connection status (admin endpoint)
app.post('/api/admin/spotify/status', authenticateAdmin, async (req, res) => {
  try {
    const connection = await getDbConnection();
    const [adminSpotify] = await connection.execute('SELECT * FROM admin_spotify ORDER BY created_at DESC LIMIT 1');
    
    if (!adminSpotify.length) {
      return res.json({ connected: false });
    }
    
    const admin = adminSpotify[0];
    const isExpired = Date.now() >= admin.expires_at;
    
    res.json({
      connected: !isExpired,
      user: {
        id: admin.spotify_user_id,
        name: admin.display_name,
        email: admin.email,
        image: admin.profile_image
      },
      expires_at: admin.expires_at,
      expired: isExpired
    });
  } catch (error) {
    console.error('Admin Spotify status error:', error);
    res.status(500).json({ error: 'Failed to check status' });
  }
});

// Disconnect admin Spotify (admin endpoint)
app.delete('/api/admin/spotify/disconnect', authenticateAdmin, async (req, res) => {
  try {
    const connection = await getDbConnection();
    await connection.execute('DELETE FROM admin_spotify');
    res.json({ success: true, message: 'Spotify kapcsolat megszakítva' });
  } catch (error) {
    console.error('Admin Spotify disconnect error:', error);
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

// Platform Analytics Endpoint
app.post('/api/admin/platform-analytics', authenticateAdmin, async (req, res) => {
  try {
    const connection = await getDbConnection();
    
    // Get platform statistics
    const [platformStats] = await connection.execute(`
      SELECT 
        platform,
        COUNT(*) as total_tracks,
        SUM(count) as total_submissions,
        AVG(count) as avg_submissions_per_track,
        MIN(firstSubmittedAt) as earliest_submission,
        MAX(lastSubmittedAt) as latest_submission,
        COUNT(CASE WHEN explicit = 1 THEN 1 END) as explicit_tracks,
        ROUND((COUNT(CASE WHEN explicit = 1 THEN 1 END) * 100.0 / COUNT(*)), 2) as explicit_percentage
      FROM submissions 
      WHERE platform IS NOT NULL
      GROUP BY platform
      ORDER BY total_submissions DESC
    `);

    // Get top tracks by platform
    const [topSpotifyTracks] = await connection.execute(`
      SELECT title, artist, count, explicit, firstSubmittedAt, lastSubmittedAt
      FROM submissions 
      WHERE platform = 'spotify'
      ORDER BY count DESC 
      LIMIT 10
    `);

    const [topDeezerTracks] = await connection.execute(`
      SELECT title, artist, count, explicit, firstSubmittedAt, lastSubmittedAt
      FROM submissions 
      WHERE platform = 'deezer'
      ORDER BY count DESC 
      LIMIT 10
    `);

    // Get daily platform usage for last 30 days
    const [dailyStats] = await connection.execute(`
      SELECT 
        DATE(lastSubmittedAt) as date,
        platform,
        COUNT(*) as tracks,
        SUM(count) as submissions
      FROM submissions 
      WHERE platform IS NOT NULL 
        AND lastSubmittedAt >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(lastSubmittedAt), platform
      ORDER BY date DESC, platform
    `);

    // Get overall statistics
    const [overallStats] = await connection.execute(`
      SELECT 
        COUNT(*) as total_unique_tracks,
        SUM(count) as total_submissions,
        COUNT(CASE WHEN platform = 'spotify' THEN 1 END) as spotify_tracks,
        COUNT(CASE WHEN platform = 'deezer' THEN 1 END) as deezer_tracks,
        COUNT(CASE WHEN platform IS NULL OR platform = '' THEN 1 END) as unknown_platform_tracks,
        COUNT(CASE WHEN explicit = 1 THEN 1 END) as total_explicit_tracks
      FROM submissions
    `);

    res.json({
      platformStats,
      topTracks: {
        spotify: topSpotifyTracks,
        deezer: topDeezerTracks
      },
      dailyStats,
      overallStats: overallStats[0]
    });

  } catch (error) {
    console.error('Platform analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch platform analytics' });
  }
});

// API Usage Statistics Endpoint
app.post('/api/admin/api-usage-stats', authenticateAdmin, async (req, res) => {
  try {
    // Return current API status and rate limiting info
    const now = Date.now();
    
    // Clean old Spotify requests
    spotifyRateLimit.requests = spotifyRateLimit.requests.filter(
      timestamp => now - timestamp < spotifyRateLimit.timeWindow
    );

    // Get current settings
    const preferredApi = await getSettingsValue('preferred_search_api', 'auto');
    const spotifyEnabled = await getSettingsValue('spotify_api_enabled', 'true') === 'true';

    const apiUsageStats = {
      spotify: {
        enabled: spotifyEnabled,
        rateLimited: isSpotifyRateLimited(),
        rateLimitedUntil: spotifyRateLimit.rateLimitedUntil,
        currentRequests: spotifyRateLimit.requests.length,
        maxRequests: spotifyRateLimit.maxRequests,
        timeWindow: spotifyRateLimit.timeWindow,
        consecutiveErrors: spotifyRateLimit.consecutiveErrors,
        hasValidToken: spotifyToken && tokenExpiresAt && now < tokenExpiresAt
      },
      deezer: {
        enabled: true, // Always available
        rateLimited: false, // Deezer has more lenient limits
        maxRequests: deezerRateLimit.maxRequests,
        timeWindow: deezerRateLimit.timeWindow
      },
      settings: {
        preferredApi,
        spotifyEnabled
      },
      serverTime: now
    };

    res.json(apiUsageStats);

  } catch (error) {
    console.error('API usage stats error:', error);
    res.status(500).json({ error: 'Failed to fetch API usage statistics' });
  }
});

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Backend API server is running on port ${PORT}`);
    // Start the database activity monitoring
    updateDbActivity();
  });
});