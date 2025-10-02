import axios from 'axios';

interface LoginResponse {
  success: boolean;
  token: string;
  user?: {
    username: string;
    role: string;
  };
}

interface Track {
  id: string;
  title: string;
  artist: string;
  thumbnail: string;
  url: string;
  explicit?: boolean;
  preview_url?: string;
  platform?: 'spotify' | 'deezer';
}



interface SubmitResponse {
  success: boolean;
  message: string;
}

interface DeleteResponse {
  success: boolean;
  message: string;
}

const API_BASE_URL = process.env.REACT_APP_API_URL || 
  (window.location.hostname === 'localhost' ? 'http://localhost:3005' : 'https://apibal.example.com');

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000, // 15 second timeout
  headers: {
    'Content-Type': 'application/json',
  },
});

let token = localStorage.getItem('adminToken');

if (token) {
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
}

export const setAuthToken = (newToken: string | null): void => {
  token = newToken;
  if (token) {
    localStorage.setItem('adminToken', token);
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    localStorage.removeItem('adminToken');
    delete api.defaults.headers.common['Authorization'];
  }
};


export const searchTracks = async (query: string): Promise<Track[]> => {
  try {
    const response = await api.get(`/api/search?q=${encodeURIComponent(query)}`);
    return response.data;
  } catch (error: any) {
    if (error.code === 'ECONNABORTED') {
      throw new Error('Request timeout - please check your connection');
    }
    if (error.response?.status === 500) {
      throw new Error('Server error - please try again later');
    }
    if (error.response?.status === 400) {
      throw new Error('Invalid search query');
    }
    throw new Error(`Search failed: ${error.message}`);
  }
};

export const submitTrack = async (track: Track, username?: string): Promise<SubmitResponse> => {
  try {
    const trackData = { 
      ...track, 
      username,
      explicit: track.explicit || false,
      platform: track.platform || 'deezer'
    };
    const response = await api.post('/api/submit', trackData);
    return response.data;
  } catch (error: any) {
    if (error.code === 'ECONNABORTED') {
      throw new Error('Request timeout - please check your connection');
    }
    if (error.response?.status === 500) {
      throw new Error('Server error - please try again later');
    }
    throw new Error(`Submit failed: ${error.message}`);
  }
};

export const adminLogin = async (username: string, password: string): Promise<LoginResponse> => {
  const response = await api.post('/api/admin/login', { username, password });
  return response.data;
};


export const getSubmissions = async (username: string, password: string): Promise<any[]> => {
  const response = await api.post(`/api/admin/submissions`, {
    username,
    password
  });
  return response.data;
};

export const deleteSubmission = async (id: number, username: string, password: string): Promise<DeleteResponse> => {
  const response = await api.delete(`/api/admin/submission/${id}`, {
    data: { username, password }
  });
  return response.data;
};

export const updateSubmissionRating = async (id: number, rating: 'ok' | 'bad' | 'middle' | null, username: string, password: string): Promise<any> => {
  const response = await api.put(`/api/admin/submission/${id}/rating`, {
    rating,
    username,
    password
  });
  return response.data;
};


export const adminLogout = async (): Promise<any> => {
  try {
    const response = await api.post('/api/admin/logout');
    return response.data;
  } catch (error) {
    // Even if the API call fails, we should clear the local token
    console.error('Logout API call failed:', error);
    return { success: true };
  }
};

export const getUserLogs = async (page: number = 1, limit: number = 50, actionType?: string, username?: string, adminUsername?: string, adminPassword?: string): Promise<any> => {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString()
  });
  
  if (actionType) params.append('action_type', actionType);
  if (username) params.append('username', username);
  
  const response = await api.post(`/api/admin/logs?${params}`, {
    username: adminUsername,
    password: adminPassword
  });
  return response.data;
};

export const changeUserPassword = async (targetUsername: string, newPassword: string, adminUsername?: string, adminPassword?: string): Promise<any> => {
  const response = await api.post('/api/admin/change-password', { 
    // Admin credentials for authentication (required by authenticateAdmin middleware)
    username: adminUsername,
    password: adminPassword,
    // Password change data
    targetUsername, 
    newPassword
  });
  return response.data;
};

export const getUsers = async (username: string, password: string): Promise<any[]> => {
  const response = await api.post('/api/admin/users/list', {
    username,
    password
  });
  return response.data;
};

export const createUser = async (newUsername: string, newPassword: string, adminUsername?: string, adminPassword?: string): Promise<any> => {
  const response = await api.post('/api/admin/users', { 
    // Admin credentials for authentication (required by authenticateAdmin middleware)
    username: adminUsername,
    password: adminPassword,
    // New user data with different field names to avoid conflicts
    newUsername: newUsername, 
    newPassword: newPassword
  });
  return response.data;
};

export const deleteUser = async (username: string, adminUsername?: string, adminPassword?: string): Promise<any> => {
  const response = await api.delete(`/api/admin/users/${username}`, {
    data: {
      // Admin credentials for authentication (required by authenticateAdmin middleware)
      username: adminUsername,
      password: adminPassword
    }
  });
  return response.data;
};

export const renameUser = async (username: string, newUsername: string, adminUsername?: string, adminPassword?: string): Promise<any> => {
  const response = await api.put(`/api/admin/users/${username}/rename`, { 
    // Admin credentials for authentication (required by authenticateAdmin middleware)
    username: adminUsername,
    password: adminPassword,
    // Rename data
    newUsername
  });
  return response.data;
};

// Settings API functions
export const getSettings = async (): Promise<any> => {
  const response = await api.get('/api/settings');
  return response.data;
};

export const getAdminSettings = async (username: string, password: string): Promise<any[]> => {
  const response = await api.post('/api/admin/settings', {
    username,
    password
  });
  return response.data;
};

export const updateAdminSettings = async (settings: any, username: string, password: string): Promise<any> => {
  const response = await api.put('/api/admin/settings', {
    username,
    password,
    settings
  });
  return response.data;
};

// Admin Spotify API functions
export const addTrackToSpotifyPlaylist = async (trackTitle: string, trackArtist: string, spotifyAccessToken: string, username: string, password: string): Promise<any> => {
  const response = await api.post('/api/admin/add-to-spotify-playlist', {
    trackTitle,
    trackArtist,
    spotifyAccessToken,
    username,
    password
  });
  return response.data;
};

export const getSpotifyPlaylistTracks = async (): Promise<any[]> => {
  const response = await api.get('/api/spotify/playlist-tracks');
  return response.data;
};

export const getWhatsPlaying = async (): Promise<any> => {
  const response = await api.get('/api/spotify/whats-playing');
  return response.data;
};

export const getAdminSpotifyStatus = async (username: string, password: string): Promise<any> => {
  const response = await api.post('/api/admin/spotify/status', {
    username,
    password
  });
  return response.data;
};

export const disconnectAdminSpotify = async (username: string, password: string): Promise<any> => {
  const response = await api.delete('/api/admin/spotify/disconnect', {
    data: { username, password }
  });
  return response.data;
};

// Public Spotify API functions
export const getSpotifyAuthUrl = async (): Promise<{ authUrl: string }> => {
  const response = await api.get('/api/spotify/auth');
  return response.data;
};

export const getSpotifyPlaylists = async (accessToken: string): Promise<any[]> => {
  const response = await api.get(`/api/spotify/playlists?access_token=${encodeURIComponent(accessToken)}`);
  return response.data;
};

export const addToSpotifyPlaylist = async (
  accessToken: string, 
  playlistId: string, 
  trackUri: string, 
  trackTitle?: string, 
  trackArtist?: string, 
  username?: string
): Promise<{ success: boolean; snapshot_id: string }> => {
  const response = await api.post('/api/spotify/add-to-playlist', {
    accessToken,
    playlistId,
    trackUri,
    trackTitle,
    trackArtist,
    username
  });
  return response.data;
};

// Platform Analytics API functions
export const getPlatformAnalytics = async (username: string, password: string): Promise<any> => {
  const response = await api.post('/api/admin/platform-analytics', {
    username,
    password
  });
  return response.data;
};

export const getApiUsageStats = async (username: string, password: string): Promise<any> => {
  const response = await api.post('/api/admin/api-usage-stats', {
    username,
    password
  });
  return response.data;
};

export default api;