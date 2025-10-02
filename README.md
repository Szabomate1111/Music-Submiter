# Music Submitter

Egy webes alkalmazás, amellyel zeneszámokat lehet keresni és beküldeni. Az alkalmazás lehetővé teszi a felhasználók számára, hogy zenék után keressenek a Spotify adatbázisában, és besubmittálják őket egy közös gyűjteménybe.

## Főbb funkcionalitások

**Zenekeresés:**
- Keresés a Spotify katalógusában 
- Automatikus debounce (500ms várakozás a keresés előtt)
- Minimum 3 karakter szükséges a kereséshez
- Intelligens cache rendszer a gyorsabb működésért
- Borítóképekkel és részletes információkkal megjelenített eredmények

**Submission rendszer:**
- Zeneszámok beküldése egyszerű kattintással
- Duplikált beküldések automatikus számlálása
- Részletes statisztikák a beküldött zenékről

**Admin felület:**
- Bejelentkezés védelemmel ellátott admin panel
- Az összes beküldött zene áttekintése és kezelése
- Rendezési lehetőségek (beküldés száma, dátum szerint)
- Nemkívánatos beküldések törlése
- Top 5 legnépszerűbb zene listája

## Telepítés és indítás

### Előfeltételek
- Node.js (v16 vagy újabb)
- MySQL adatbázis (XAMPP ajánlott)
- Spotify Developer fiók

### Lépésről lépésre telepítés

**1. Függőségek telepítése**
```bash
# Backend függőségek
cd backend
npm install

# Frontend függőségek  
cd ../frontend
npm install
```

**2. Adatbázis beállítása**
- Indítsd el az XAMPP-ot vagy a MySQL szervert
- Hozz létre egy új adatbázist: `spotify_search`
- A táblák automatikusan létrejönnek az első indításkor

**3. Konfigurációs fájl beállítása**
```bash
# Másold át a példa konfigurációt
cp frontend/.env.example frontend/.env
```

Szerkeszd a `.env` fájlt a saját adataiddal:
```env
# Spotify API kulcsok (szerezd be: https://developer.spotify.com/)
REACT_APP_SPOTIFY_CLIENT_ID=a_te_client_id
REACT_APP_SPOTIFY_CLIENT_SECRET=a_te_client_secret

# Admin jelszó
REACT_APP_ADMIN_PASSWORD=biztonságos_jelszó

# Adatbázis beállítások
REACT_APP_DB_HOST=localhost
REACT_APP_DB_USER=root  
REACT_APP_DB_PASSWORD=adatbázis_jelszó
REACT_APP_DB_NAME=spotify_search
```

**4. Alkalmazás indítása**
```bash
# Backend indítása (backend mappából)
npm run dev

# Frontend indítása (új terminálablakban, frontend mappából)
npm start
```

**Elérés:**
- Webes felület: http://localhost:3000
- API: http://localhost:5000

## Használat

### Zenekeresés oldal
1. Írj be egy keresési kifejezést (minimum 3 karakter)
2. Böngészd az eredményeket borítóképekkel és zene információkkal
3. Kattints a "Submit" gombra a zenék adatbázisba küldéséhez
4. Ha ugyanazt a zenét többször küldöd be, a számláló növekszik

### Admin felület
1. Navigálj a `/admin` oldalra
2. Jelentkezz be a beállított jelszóval
3. Tekintsd át a statisztikákat és beküldött zenéket
4. Rendezd a listát beküldések száma vagy dátum szerint
5. Törölj nemkívánatos beküldéseket
6. Nézd meg a Top 5 legnépszerűbb zenét

## API végpontok

- `GET /api/search?q=keresés` - Zenék keresése a Spotify-ban
- `POST /api/submit` - Zene beküldése az adatbázisba
- `POST /api/admin/login` - Admin bejelentkezés
- `GET /api/admin/submissions` - Összes beküldés lekérése (admin)
- `DELETE /api/admin/submission/:id` - Beküldés törlése (admin)

## Adatbázis struktúra

Az alkalmazás automatikusan létrehozza az összes szükséges táblát az első indításkor. Egyszerűen hozz létre egy üres adatbázist `spotify_search` néven, és a következő táblák automatikusan létrejönnek:

**Fő táblák:**
- `submissions` - Beküldött zeneszámok tárolása beküldési számokkal
- `users` - Admin felhasználó kezelés
- `user_logs` - Aktivitás naplózás és analitika
- `device_sessions` - Munkamenet követés sebességkorlátozáshoz
- `settings` - Alkalmazás konfiguráció
- `admin_spotify` - Spotify integráció admin funkciókhoz

**Manuális adatbázis beállítás (Opcionális):**
Ha inkább manuálisan szeretnéd létrehozni az adatbázist, futtasd ezeket az SQL parancsokat:

```sql
-- Adatbázis létrehozása
CREATE DATABASE spotify_search;
USE spotify_search;

-- Fő submissions tábla
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

-- Admin felhasználók tábla
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role ENUM('owner', 'admin') DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Aktivitás naplók tábla
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

-- Munkamenet követés tábla
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

-- Beállítások tábla
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

-- Spotify admin integráció tábla
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

## Technológiai stack

**Frontend:**
- React 18 - Felhasználói felület
- React Router DOM - Navigáció
- Tailwind CSS - Stílusok
- Axios - HTTP kérések

**Backend:**
- Node.js - Szerver környezet
- Express.js - Web framework
- MySQL2 - Adatbázis kapcsolat
- JSON Web Tokens - Autentikáció
- bcryptjs - Jelszó titkosítás

## Fejlesztői környezet

```bash
# Backend fejlesztés automatikus újraindítással
cd backend
npm run dev

# Frontend fejlesztés
cd frontend  
npm start
```

## Licenc

MIT License