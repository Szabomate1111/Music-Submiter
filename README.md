# Music Submitter

A web application for searching and submitting music tracks. Users can search the Spotify database and submit tracks to a shared collection for community voting and discovery.

## Key Features

**Music Search:**
- Search through Spotify's music catalog
- Automatic debounce (500ms delay before search)
- Minimum 3 characters required for search
- Intelligent caching system for faster performance
- Results displayed with cover art and detailed track information

**Submission System:**
- Submit music tracks with a simple click
- Automatic counting of duplicate submissions
- Detailed statistics about submitted tracks

**Admin Interface:**
- Login-protected admin panel
- Overview and management of all submitted tracks
- Sorting options (by submission count, date)
- Delete unwanted submissions
- Top 5 most popular tracks list

## Installation and Setup

### Prerequisites
- Node.js (v16 or higher)
- MySQL database (XAMPP recommended)
- Spotify Developer account

### Step-by-step Installation

**1. Install Dependencies**
```bash
# Backend dependencies
cd backend
npm install

# Frontend dependencies  
cd ../frontend
npm install
```

**2. Database Setup**
- Start XAMPP or MySQL server
- Create a new database: `spotify_search`
- Tables will be created automatically on first run

**3. Environment Configuration**
```bash
# Copy the example configuration
cp frontend/.env.example frontend/.env
```

Edit the `.env` file with your data:
```env
# Spotify API keys (get from: https://developer.spotify.com/)
REACT_APP_SPOTIFY_CLIENT_ID=your_client_id
REACT_APP_SPOTIFY_CLIENT_SECRET=your_client_secret

# Admin password
REACT_APP_ADMIN_PASSWORD=secure_password

# Database settings
REACT_APP_DB_HOST=localhost
REACT_APP_DB_USER=root  
REACT_APP_DB_PASSWORD=database_password
REACT_APP_DB_NAME=spotify_search
```

**4. Run Application**
```bash
# Start backend (from backend directory)
npm run dev

# Start frontend (new terminal window, from frontend directory)
npm start
```

**Access:**
- Web interface: http://localhost:3000
- API: http://localhost:5000

## Usage

### Search Page
1. Enter a search query (minimum 3 characters)
2. Browse results with cover art and track information
3. Click the "Submit" button to send tracks to the database
4. If you submit the same track multiple times, the counter increases

### Admin Interface
1. Navigate to the `/admin` page
2. Log in with the configured password
3. Review statistics and submitted tracks
4. Sort the list by submission count or date
5. Delete unwanted submissions
6. View the Top 5 most popular tracks

## API Endpoints

- `GET /api/search?q=query` - Search tracks on Spotify
- `POST /api/submit` - Submit track to database
- `POST /api/admin/login` - Admin login
- `GET /api/admin/submissions` - Get all submissions (admin)
- `DELETE /api/admin/submission/:id` - Delete submission (admin)

## Database Structure

The application will automatically create all necessary tables on first run. Simply create an empty database named `spotify_search` and the following tables will be created automatically:

**Main Tables:**
- `submissions` - Stores submitted music tracks with submission counts
- `users` - Admin user management 
- `user_logs` - Activity logging and analytics
- `device_sessions` - Session tracking for rate limiting
- `settings` - Application configuration
- `admin_spotify` - Spotify integration for admin features

**Manual Database Setup (Optional):**
If you prefer to create the database manually, run these SQL commands:

```sql
-- Create database
CREATE DATABASE spotify_search;
USE spotify_search;

-- Main submissions table
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
  platform ENUM('spotify', 'deezer') DEFAULT 'spotify',
  rating ENUM('ok', 'bad', 'middle') DEFAULT NULL,
  INDEX idx_spotify_id (spotifyId),
  INDEX idx_count (count),
  INDEX idx_submitted_at (lastSubmittedAt)
);

-- Admin users table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role ENUM('owner', 'admin') DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Activity logs table
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
  INDEX idx_created_at (created_at)
);

-- Session tracking table
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
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  setting_key VARCHAR(100) UNIQUE NOT NULL,
  setting_value TEXT,
  description TEXT,
  updated_by VARCHAR(50),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_setting_key (setting_key)
);

-- Spotify admin integration table
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
);
```

## Technology Stack

**Frontend:**
- React 18 - User interface
- React Router DOM - Navigation
- Tailwind CSS - Styling
- Axios - HTTP requests

**Backend:**
- Node.js - Server environment
- Express.js - Web framework
- MySQL2 - Database connection
- JSON Web Tokens - Authentication
- bcryptjs - Password encryption

## Development Environment

```bash
# Backend development with automatic restart
cd backend
npm run dev

# Frontend development
cd frontend  
npm start
```

## License

MIT License