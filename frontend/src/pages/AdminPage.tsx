import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faExpand, faTimes, faTrash, faMusic, faSignOutAlt, faHome, faCog, faPlus, faExclamationTriangle, faCheck, faThumbsUp, faThumbsDown, faExclamationCircle } from '@fortawesome/free-solid-svg-icons';
import { faSpotify } from '@fortawesome/free-brands-svg-icons';
import { adminLogin, getSubmissions, deleteSubmission, updateSubmissionRating, setAuthToken, adminLogout, getUserLogs, changeUserPassword, getUsers, createUser, deleteUser, renameUser, getAdminSettings, updateAdminSettings, addTrackToSpotifyPlaylist, getAdminSpotifyStatus, disconnectAdminSpotify, getSpotifyPlaylists, addToSpotifyPlaylist, submitTrack, getPlatformAnalytics, getApiUsageStats } from '../utils/api';

interface Submission {
  id: number;
  spotifyId: string;
  title: string;
  artist: string;
  thumbnail: string;
  url: string;
  count: number;
  firstSubmittedAt: string;
  lastSubmittedAt: string;
  explicit?: boolean;
  platform?: 'spotify' | 'deezer';
  rating?: 'ok' | 'bad' | 'middle' | null;
}

interface User {
  username: string;
  role: string;
}

const AdminPage: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [storedCredentials, setStoredCredentials] = useState<{username: string, password: string} | null>(null);
  const [loginError, setLoginError] = useState<string>('');
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [sortBy, setSortBy] = useState<string>('count');
  const [sortOrder, setSortOrder] = useState<string>('DESC');
  const [showModal, setShowModal] = useState<boolean>(false);
  const [modalType, setModalType] = useState<'submissions' | 'logs'>('submissions');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [logs, setLogs] = useState<any[]>([]);
  const [showLogs, setShowLogs] = useState<boolean>(false);
  const [logsLoading, setLogsLoading] = useState<boolean>(false);
  const [showUserManagement, setShowUserManagement] = useState<boolean>(false);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [usersLoading, setUsersLoading] = useState<boolean>(false);
  const [newPassword, setNewPassword] = useState<string>('');
  const [passwordChangeLoading, setPasswordChangeLoading] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>('');
  const [newUserRole, setNewUserRole] = useState<'admin' | 'owner'>('admin');
  const [userActionLoading, setUserActionLoading] = useState<boolean>(false);
  const [addingToPlaylist, setAddingToPlaylist] = useState<number | null>(null);
  
  // Spotify state
  const [spotifyAccessToken, setSpotifyAccessToken] = useState<string | null>(null);
  const [spotifyUser, setSpotifyUser] = useState<{name: string, image: string} | null>(null);
  
  // Settings state
  const [showSettings, setShowSettings] = useState<boolean>(false);
  const [settings, setSettings] = useState<any[]>([]);
  const [settingsLoading, setSettingsLoading] = useState<boolean>(false);
  const [settingsValues, setSettingsValues] = useState<Record<string, string>>({});
  
  // Notification system
  const [notifications, setNotifications] = useState<{id: string, message: string, type: 'success' | 'error' | 'info'}[]>([]);
  
  // Confirmation modal system
  const [showConfirmation, setShowConfirmation] = useState<boolean>(false);
  const [confirmationData, setConfirmationData] = useState<{message: string, onConfirm: () => void, onCancel?: () => void} | null>(null);
  
  // Spotify authentication state
  const [spotifyConnected, setSpotifyConnected] = useState<boolean>(false);
  const [spotifyTokenExpiry, setSpotifyTokenExpiry] = useState<number>(0);
  
  // Admin Spotify "What's Playing" state
  const [adminSpotifyConnected, setAdminSpotifyConnected] = useState<boolean>(false);
  const [adminSpotifyUser, setAdminSpotifyUser] = useState<any>(null);
  const [adminSpotifyLoading, setAdminSpotifyLoading] = useState<boolean>(false);
  
  // Analytics state
  const [showAnalytics, setShowAnalytics] = useState<boolean>(false);
  const [analyticsData, setAnalyticsData] = useState<any>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(false);
  const [apiUsageStats, setApiUsageStats] = useState<any>(null);
  
  const showNotification = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Math.random().toString(36).substr(2, 9);
    setNotifications(prev => [...prev, { id, message, type }]);
    
    // Auto remove after 4 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(notif => notif.id !== id));
    }, 4000);
  };
  
  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(notif => notif.id !== id));
  };
  
  const showConfirm = (message: string, onConfirm: () => void, onCancel?: () => void) => {
    setConfirmationData({ message, onConfirm, onCancel });
    setShowConfirmation(true);
  };

  // Handle Spotify authentication callback
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const spotifyToken = urlParams.get('spotify_access_token');
    const spotifyUserName = urlParams.get('spotify_user_name');
    const spotifyUserImage = urlParams.get('spotify_user_image');
    
    if (spotifyToken) {
      setSpotifyAccessToken(spotifyToken);
      localStorage.setItem('admin_spotify_access_token', spotifyToken);
      
      if (spotifyUserName) {
        const userData = {
          name: decodeURIComponent(spotifyUserName),
          image: decodeURIComponent(spotifyUserImage || '')
        };
        setSpotifyUser(userData);
        localStorage.setItem('admin_spotify_user', JSON.stringify(userData));
      }
      
      // Remove tokens from URL
      window.history.replaceState({}, document.title, window.location.pathname);
      
      showNotification(`Spotify bejelentkezés sikeres! Üdv, ${decodeURIComponent(spotifyUserName || '')}!`, 'success');
    } else {
      // Check for stored token and user
      const storedToken = localStorage.getItem('admin_spotify_access_token');
      const storedUser = localStorage.getItem('admin_spotify_user');
      if (storedToken) {
        setSpotifyAccessToken(storedToken);
        if (storedUser) {
          setSpotifyUser(JSON.parse(storedUser));
        }
      }
    }
  }, []);


  const handleSpotifyAuth = () => {
    showNotification('Átirányítás Spotify bejelentkezéshez...', 'info');
    window.location.href = 'https://apibal.example.com/api/spotify/auth';
  };

  const handleAddToPlaylist = async (submission: Submission) => {
    if (!spotifyAccessToken) {
      handleSpotifyAuth();
      return;
    }
    
    setAddingToPlaylist(submission.id);
    
    try {
      // Fix Spotify playlist ID
      const FIXED_PLAYLIST_ID = '2Hkj2Y2LWrTZmPtkSz6MMZ';
      
      // Megpróbáljuk megkeresni a zenét Spotify-on a cím és előadó alapján
      const searchQuery = `${submission.title} ${submission.artist}`;
      const searchResponse = await fetch(`${process.env.REACT_APP_API_URL || 'https://apibal.example.com'}/api/spotify/search?q=${encodeURIComponent(searchQuery)}`, {
        headers: {
          'Authorization': `Bearer ${spotifyAccessToken}`
        }
      });
      
      let trackUri = submission.url; // fallback to original URL
      
      if (searchResponse.ok) {
        const searchData = await searchResponse.json();
        if (searchData.tracks && searchData.tracks.items && searchData.tracks.items.length > 0) {
          // Használjuk az első találatot
          trackUri = `spotify:track:${searchData.tracks.items[0].id}`;
        }
      }
      
      await addToSpotifyPlaylist(
        spotifyAccessToken, 
        FIXED_PLAYLIST_ID, 
        trackUri, 
        submission.title, 
        submission.artist, 
        currentUser?.username
      );
      
      showNotification(`"${submission.title}" sikeresen hozzáadva a Sulibál Spotify playlisthez!`, 'success');
    } catch (error) {
      console.error('Add to playlist error:', error);
      showNotification('Hiba történt a Spotify lejátszási listához adás során!', 'error');
    } finally {
      setAddingToPlaylist(null);
    }
  };

  
  const handleConfirm = () => {
    if (confirmationData?.onConfirm) {
      confirmationData.onConfirm();
    }
    setShowConfirmation(false);
    setConfirmationData(null);
  };
  
  const handleCancel = () => {
    if (confirmationData?.onCancel) {
      confirmationData.onCancel();
    }
    setShowConfirmation(false);
    setConfirmationData(null);
  };

  const fetchSettings = async (): Promise<void> => {
    if (currentUser?.role !== 'owner' || !storedCredentials) return;
    
    setSettingsLoading(true);
    try {
      const settingsData = await getAdminSettings(storedCredentials.username, storedCredentials.password);
      setSettings(settingsData);
      
      // Create settingsValues object for form state
      const values: Record<string, string> = {};
      settingsData.forEach(setting => {
        values[setting.setting_key] = setting.setting_value;
      });
      setSettingsValues(values);
    } catch (error) {
      console.error('Error fetching settings:', error);
      showNotification('Hiba a beállítások betöltésekor', 'error');
    } finally {
      setSettingsLoading(false);
    }
  };

  const handleSettingsUpdate = async (): Promise<void> => {
    if (!storedCredentials) return;
    
    setSettingsLoading(true);
    try {
      await updateAdminSettings(settingsValues, storedCredentials.username, storedCredentials.password);
      showNotification('Beállítások sikeresen frissítve!', 'success');
      fetchSettings(); // Refresh settings
    } catch (error: any) {
      console.error('Error updating settings:', error);
      const errorMessage = error.response?.data?.error || 'Hiba a beállítások frissítésekor';
      showNotification(errorMessage, 'error');
    } finally {
      setSettingsLoading(false);
    }
  };

  const fetchUsers = async (): Promise<void> => {
    if (currentUser?.role !== 'owner' || !storedCredentials) return;
    
    setUsersLoading(true);
    try {
      const usersData = await getUsers(storedCredentials.username, storedCredentials.password);
      setAllUsers(usersData);
    } catch (error) {
      console.error('Error fetching users:', error);
      showNotification('Hiba a felhasználók betöltésekor', 'error');
    } finally {
      setUsersLoading(false);
    }
  };

  const handleCreateUser = async (username: string, password: string): Promise<boolean> => {
    if (!username.trim()) {
      showNotification('Kérlek adj meg egy felhasználónevet!', 'error');
      return false;
    }
    
    if (username.length < 3) {
      showNotification('A felhasználónévnek legalább 3 karakter hosszúnak kell lennie!', 'error');
      return false;
    }
    
    if (!password.trim()) {
      showNotification('Kérlek adj meg egy jelszót!', 'error');
      return false;
    }
    
    if (password.length < 4) {
      showNotification('A jelszónak legalább 4 karakter hosszúnak kell lennie!', 'error');
      return false;
    }
    
    if (!storedCredentials || !storedCredentials.username || !storedCredentials.password) {
      showNotification('Hiányzó vagy érvénytelen hitelesítési adatok! Kérlek jelentkezz be újra.', 'error');
      console.error('Stored credentials missing or invalid:', storedCredentials);
      return false;
    }
    
    setUserActionLoading(true);
    
    try {
      await createUser(username, password, storedCredentials.username, storedCredentials.password);
      showNotification(`${username} admin felhasználó sikeresen létrehozva!`, 'success');
      fetchUsers(); // Refresh user list
      return true;
    } catch (error: any) {
      console.error('Create user error:', error);
      const errorMessage = error.response?.data?.error || 'Hiba a felhasználó létrehozásakor';
      showNotification(errorMessage, 'error');
      return false;
    } finally {
      setUserActionLoading(false);
    }
  };

  const handleDeleteUser = async (username: string): Promise<void> => {
    if (!storedCredentials || !storedCredentials.username || !storedCredentials.password) {
      showNotification('Hiányzó vagy érvénytelen hitelesítési adatok! Kérlek jelentkezz be újra.', 'error');
      return;
    }
    
    showConfirm(
      `Biztosan törölni szeretnéd a ${username} felhasználót?`,
      async () => {
        setUserActionLoading(true);
        
        try {
          await deleteUser(username, storedCredentials!.username, storedCredentials!.password);
          showNotification(`${username} felhasználó sikeresen törölve!`, 'success');
          fetchUsers(); // Refresh user list
        } catch (error: any) {
          console.error('Delete user error:', error);
          const errorMessage = error.response?.data?.error || 'Hiba a felhasználó törlésekor';
          showNotification(errorMessage, 'error');
        } finally {
          setUserActionLoading(false);
        }
      }
    );
  };

  const handleRenameUser = async (username: string, newUsername: string): Promise<boolean> => {
    if (!newUsername.trim()) {
      showNotification('Kérlek adj meg egy új felhasználónevet!', 'error');
      return false;
    }
    
    if (newUsername.length < 3) {
      showNotification('A felhasználónévnek legalább 3 karakter hosszúnak kell lennie!', 'error');
      return false;
    }
    
    if (newUsername === username) {
      showNotification('Az új felhasználónév megegyezik a régivel!', 'error');
      return false;
    }
    
    if (!storedCredentials || !storedCredentials.username || !storedCredentials.password) {
      showNotification('Hiányzó vagy érvénytelen hitelesítési adatok! Kérlek jelentkezz be újra.', 'error');
      return false;
    }
    
    setUserActionLoading(true);
    
    try {
      await renameUser(username, newUsername, storedCredentials.username, storedCredentials.password);
      showNotification(`Felhasználó átnevezve: ${username} → ${newUsername}`, 'success');
      fetchUsers(); // Refresh user list
      return true;
    } catch (error: any) {
      console.error('Rename user error:', error);
      const errorMessage = error.response?.data?.error || 'Hiba a felhasználó átnevezésekor';
      showNotification(errorMessage, 'error');
      return false;
    } finally {
      setUserActionLoading(false);
    }
  };

  // Analytics functions
  const fetchAnalytics = async (): Promise<void> => {
    if (currentUser?.role !== 'owner' || !storedCredentials) return;
    
    setAnalyticsLoading(true);
    try {
      const [platformData, apiUsageData] = await Promise.all([
        getPlatformAnalytics(storedCredentials.username, storedCredentials.password),
        getApiUsageStats(storedCredentials.username, storedCredentials.password)
      ]);
      
      setAnalyticsData(platformData);
      setApiUsageStats(apiUsageData);
    } catch (error) {
      console.error('Error fetching analytics:', error);
      showNotification('Hiba az analitika betöltésekor', 'error');
    } finally {
      setAnalyticsLoading(false);
    }
  };

  useEffect(() => {
    const userData = localStorage.getItem('currentUser');
    const credentialsData = localStorage.getItem('adminCredentials');
    const spotifyData = localStorage.getItem('spotifyData');
    
    if (userData && credentialsData) {
      try {
        const user = JSON.parse(userData);
        const credentials = JSON.parse(credentialsData);
        setCurrentUser(user);
        setStoredCredentials(credentials);
        setIsAuthenticated(true);
        // Don't call fetchSubmissions here, it will be called when storedCredentials is set
      } catch (error) {
        // Invalid data, clear everything
        localStorage.removeItem('currentUser');
        localStorage.removeItem('adminCredentials');
      }
    }
    
    if (spotifyData) {
      try {
        const spotify = JSON.parse(spotifyData);
        if (spotify.expires_at > Date.now()) {
          setSpotifyConnected(true);
          setSpotifyUser({
            name: spotify.user.display_name || spotify.user.id,
            image: spotify.user.images?.[0]?.url || ''
          });
          setSpotifyAccessToken(spotify.access_token);
          setSpotifyTokenExpiry(spotify.expires_at);
        } else {
          localStorage.removeItem('spotifyData');
        }
      } catch (error) {
        localStorage.removeItem('spotifyData');
      }
    }
    
    // Handle Spotify OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    const spotifySuccess = urlParams.get('spotify_success');
    const spotifyError = urlParams.get('spotify_error');
    const adminSpotifySuccess = urlParams.get('admin_spotify_success');
    const adminSpotifyError = urlParams.get('admin_spotify_error');
    
    if (spotifySuccess) {
      try {
        const spotifyData = JSON.parse(decodeURIComponent(spotifySuccess));
        setSpotifyConnected(true);
        setSpotifyUser({
          name: spotifyData.user.display_name || spotifyData.user.id,
          image: spotifyData.user.images?.[0]?.url || ''
        });
        setSpotifyAccessToken(spotifyData.access_token);
        setSpotifyTokenExpiry(spotifyData.expires_at);
        localStorage.setItem('spotifyData', JSON.stringify(spotifyData));
        showNotification('Spotify bejelentkezés sikeres!', 'success');
      } catch (error) {
        showNotification('Spotify bejelentkezési hiba!', 'error');
      }
      
      // Clean up URL
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);
    }
    
    if (spotifyError) {
      const errorMessages = {
        no_code: 'Spotify engedélyezés megszakítva',
        auth_failed: 'Spotify bejelentkezési hiba'
      };
      showNotification(errorMessages[spotifyError as keyof typeof errorMessages] || 'Spotify bejelentkezési hiba', 'error');
      
      // Clean up URL
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);
    }
    
    // Handle Admin Spotify OAuth callback
    if (adminSpotifySuccess) {
      showNotification('Admin Spotify fiók sikeresen összekapcsolva!', 'success');
      checkAdminSpotifyStatus();
      
      // Clean up URL
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);
    }
    
    if (adminSpotifyError) {
      const errorMessages = {
        no_code: 'Admin Spotify engedélyezés megszakítva',
        auth_failed: 'Admin Spotify bejelentkezési hiba'
      };
      showNotification(errorMessages[adminSpotifyError as keyof typeof errorMessages] || 'Admin Spotify bejelentkezési hiba', 'error');
      
      // Clean up URL
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);
    }
  }, []);


  const handleLogin = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault();
    setLoginError('');
    
    if (!username.trim()) {
      setLoginError('Felhasználónév kötelező');
      return;
    }
    
    try {
      const response = await adminLogin(username, password);
      if (response.success && response.user) {
        setCurrentUser(response.user);
        setStoredCredentials({ username, password });
        localStorage.setItem('currentUser', JSON.stringify(response.user));
        localStorage.setItem('adminCredentials', JSON.stringify({ username, password }));
        setIsAuthenticated(true);
        setUsername('');
        setPassword('');
        fetchSubmissions();
      }
    } catch (error) {
      setLoginError('Érvénytelen felhasználónév vagy jelszó');
    }
  };

  const handleLogout = async (): Promise<void> => {
    setCurrentUser(null);
    setStoredCredentials(null);
    localStorage.removeItem('currentUser');
    localStorage.removeItem('adminCredentials');
    setIsAuthenticated(false);
    setSubmissions([]);
    setLogs([]);
  };

  const fetchSubmissions = async (): Promise<void> => {
    if (!storedCredentials) return;
    
    setLoading(true);
    try {
      const data = await getSubmissions(storedCredentials.username, storedCredentials.password);
      setSubmissions(data);
    } catch (error) {
      console.error('Error fetching submissions:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSort = (newSortBy: string): void => {
    const newOrder = sortBy === newSortBy && sortOrder === 'DESC' ? 'ASC' : 'DESC';
    setSortBy(newSortBy);
    setSortOrder(newOrder);
  };

  const handleDelete = async (id: number): Promise<void> => {
    if (!storedCredentials) return;
    
    showConfirm(
      'Biztosan törlöd ezt a beküldést?',
      async () => {
        try {
          await deleteSubmission(id, storedCredentials.username, storedCredentials.password);
          setSubmissions(prev => prev.filter(sub => sub.id !== id));
          showNotification('Zeneszám sikeresen törölve!', 'success');
        } catch (error) {
          console.error('Error deleting submission:', error);
          showNotification('Hiba a zeneszám törlésekor', 'error');
        }
      }
    );
  };

  const handleRating = async (id: number, newRating: 'ok' | 'bad' | 'middle' | null): Promise<void> => {
    if (!storedCredentials) return;
    
    try {
      await updateSubmissionRating(id, newRating, storedCredentials.username, storedCredentials.password);
      
      // Update local state
      setSubmissions(prev => prev.map(sub => 
        sub.id === id ? { ...sub, rating: newRating } : sub
      ));
      
      const ratingText = newRating ? newRating.toUpperCase() : 'NINCS';
      showNotification(`Rating beállítva: ${ratingText}`, 'success');
    } catch (error) {
      console.error('Error updating rating:', error);
      showNotification('Hiba a rating frissítésekor', 'error');
    }
  };

  const handleAddToSpotify = async (trackTitle: string, trackArtist: string): Promise<void> => {
    if (!storedCredentials) return;
    
    if (!spotifyConnected || !spotifyAccessToken) {
      showNotification('Először jelentkezz be Spotify-ba!', 'error');
      return;
    }
    
    // Check if token is expired
    if (Date.now() >= spotifyTokenExpiry) {
      showNotification('Spotify token lejárt, jelentkezz be újra!', 'error');
      handleSpotifyLogout();
      return;
    }
    
    try {
      const result = await addTrackToSpotifyPlaylist(trackTitle, trackArtist, spotifyAccessToken, storedCredentials.username, storedCredentials.password);
      showNotification(`Zeneszám sikeresen hozzáadva a Spotify playlisthez: ${result.spotifyTrack.name}`, 'success');
    } catch (error: any) {
      console.error('Error adding to Spotify:', error);
      const errorMessage = error.response?.data?.error || 'Hiba a zeneszám Spotify playlisthez adásakor';
      showNotification(errorMessage, 'error');
      
      if (error.response?.status === 401) {
        handleSpotifyLogout();
      }
    }
  };

  const handleSpotifyLogin = () => {
    showNotification('Átirányítás Spotify bejelentkezéshez...', 'info');
    window.location.href = 'https://apibal.example.com/api/spotify/auth';
  };

  const handleSpotifyLogout = () => {
    setSpotifyConnected(false);
    setSpotifyUser(null);
    setSpotifyAccessToken(null);
    setSpotifyTokenExpiry(0);
    localStorage.removeItem('spotifyData');
    showNotification('Spotify kijelentkezés sikeres!', 'success');
  };

  const checkAdminSpotifyStatus = async () => {
    if (!storedCredentials) return;
    
    try {
      setAdminSpotifyLoading(true);
      const status = await getAdminSpotifyStatus(storedCredentials.username, storedCredentials.password);
      setAdminSpotifyConnected(status.connected);
      setAdminSpotifyUser(status.user || null);
    } catch (error) {
      console.error('Error checking admin Spotify status:', error);
      setAdminSpotifyConnected(false);
      setAdminSpotifyUser(null);
    } finally {
      setAdminSpotifyLoading(false);
    }
  };

  const handleAdminSpotifyConnect = () => {
    showNotification('Átirányítás admin Spotify bejelentkezéshez...', 'info');
    window.location.href = 'https://apibal.example.com/api/admin/spotify/connect';
  };

  const handleAdminSpotifyDisconnect = async () => {
    if (!storedCredentials) return;
    
    showConfirm(
      'Biztosan megszakítod az admin Spotify kapcsolatot?',
      async () => {
        try {
          await disconnectAdminSpotify(storedCredentials.username, storedCredentials.password);
          setAdminSpotifyConnected(false);
          setAdminSpotifyUser(null);
          showNotification('Admin Spotify kapcsolat megszakítva!', 'success');
        } catch (error) {
          console.error('Error disconnecting admin Spotify:', error);
          showNotification('Hiba a kapcsolat megszakításakor', 'error');
        }
      }
    );
  };


  const fetchLogs = async (): Promise<void> => {
    if (currentUser?.role !== 'owner' || !storedCredentials) return;
    
    setLogsLoading(true);
    try {
      const data = await getUserLogs(1, 100, undefined, undefined, storedCredentials.username, storedCredentials.password);
      setLogs(data.logs);
    } catch (error) {
      console.error('Error fetching logs:', error);
      showNotification('Hiba a logok betöltésekor', 'error');
    } finally {
      setLogsLoading(false);
    }
  };

  const formatLogDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString('hu-HU');
  };

  const getActionTypeText = (actionType: string): string => {
    const types: Record<string, string> = {
      'login': 'Bejelentkezés',
      'logout': 'Kilépés',
      'track_submit': 'Zeneszám beküldés',
      'admin_delete': 'Zeneszám törlés',
      'admin_background_upload': 'Háttérkép feltöltés',
      'admin_password_change': 'Jelszó módosítás'
    };
    return types[actionType] || actionType;
  };

  const handlePasswordChange = async (username: string, password: string): Promise<boolean> => {
    if (!password.trim()) {
      showNotification('Kérlek adj meg egy új jelszót!', 'error');
      return false;
    }
    
    if (password.length < 4) {
      showNotification('A jelszónak legalább 4 karakter hosszúnak kell lennie!', 'error');
      return false;
    }
    
    setPasswordChangeLoading(true);
    
    try {
      if (!storedCredentials) {
        showNotification('Hiányzó hitelesítési adatok!', 'error');
        return false;
      }
      await changeUserPassword(username, password, storedCredentials.username, storedCredentials.password);
      showNotification(`${username} felhasználó jelszava sikeresen módosítva!`, 'success');
      return true;
    } catch (error) {
      console.error('Password change error:', error);
      showNotification('Hiba a jelszó módosítása során', 'error');
      return false;
    } finally {
      setPasswordChangeLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated && storedCredentials) {
      fetchSubmissions();
      checkAdminSpotifyStatus();
      if (currentUser?.role === 'owner') {
        fetchLogs();
      }
    }
  }, [storedCredentials]);

  useEffect(() => {
    if (isAuthenticated && currentUser?.role === 'owner' && storedCredentials) {
      fetchLogs();
    }
  }, [isAuthenticated, currentUser, storedCredentials]);

  useEffect(() => {
    if (showUserManagement && currentUser?.role === 'owner' && storedCredentials) {
      fetchUsers();
    }
  }, [showUserManagement, currentUser, storedCredentials]);

  useEffect(() => {
    if (showSettings && currentUser?.role === 'owner' && storedCredentials) {
      fetchSettings();
    }
  }, [showSettings, currentUser, storedCredentials]);

  useEffect(() => {
    if (showAnalytics && currentUser?.role === 'owner' && storedCredentials) {
      fetchAnalytics();
    }
  }, [showAnalytics, currentUser, storedCredentials]);

  // Disable/enable body scroll when modals are open
  useEffect(() => {
    if (showModal || showUserManagement || showSettings || showConfirmation || showAnalytics) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    
    // Cleanup when component unmounts
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [showModal, showUserManagement, showSettings, showConfirmation, showAnalytics]);

  // Clear search when modal closes or modal type changes
  useEffect(() => {
    if (!showModal || modalType !== 'submissions') {
      setSearchQuery('');
    }
  }, [showModal, modalType]);

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  const getSortIcon = (column: string): string => {
    if (sortBy !== column) return '↕️';
    return sortOrder === 'DESC' ? '↓' : '↑';
  };

  // Client-side sorting
  const sortedSubmissions = React.useMemo(() => {
    if (!submissions.length) return [];

    // First filter by search query
    let filteredSubmissions = submissions;
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filteredSubmissions = submissions.filter(submission =>
        submission.title.toLowerCase().includes(query) ||
        submission.artist.toLowerCase().includes(query) ||
        (submission.platform && submission.platform.toLowerCase().includes(query))
      );
    }

    return [...filteredSubmissions].sort((a, b) => {
      let aValue: any;
      let bValue: any;

      switch (sortBy) {
        case 'count':
          aValue = a.count;
          bValue = b.count;
          break;
        case 'title':
          aValue = a.title.toLowerCase();
          bValue = b.title.toLowerCase();
          break;
        case 'artist':
          aValue = a.artist.toLowerCase();
          bValue = b.artist.toLowerCase();
          break;
        case 'firstSubmittedAt':
        case 'lastSubmittedAt':
          aValue = new Date(a[sortBy]).getTime();
          bValue = new Date(b[sortBy]).getTime();
          break;
        case 'rating':
          // Custom rating sort: ok > middle > bad > null
          const getRatingOrder = (rating: string | null | undefined): number => {
            switch (rating) {
              case 'ok': return 1;
              case 'middle': return 2;
              case 'bad': return 3;
              default: return 4; // null, undefined, or other
            }
          };
          aValue = getRatingOrder(a.rating);
          bValue = getRatingOrder(b.rating);
          break;
        default:
          return 0;
      }

      if (aValue < bValue) return sortOrder === 'ASC' ? -1 : 1;
      if (aValue > bValue) return sortOrder === 'ASC' ? 1 : -1;
      return 0;
    });
  }, [submissions, sortBy, sortOrder, searchQuery]);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center" 
           style={{
             backgroundImage: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)',
             backgroundSize: 'cover',
             backgroundRepeat: 'no-repeat'
           }}>
        <div className="absolute inset-0 backdrop-blur-sm"></div>
        <div className="max-w-md w-full relative z-10">
          <div className="bg-gray-800/90 backdrop-blur-md rounded-lg shadow-lg p-8 border border-gray-600/50">
            <div className="flex justify-between items-center mb-8">
              <h1 className="text-2xl font-bold text-white">Admin Bejelentkezés</h1>
              <Link to="/" className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors font-medium text-sm flex items-center gap-2">
                <FontAwesomeIcon icon={faHome} />
                Home
              </Link>
            </div>
            
            <form onSubmit={handleLogin}>
              <div className="mb-4">
                <label htmlFor="username" className="block text-sm font-medium text-white mb-2">
                  Felhasználónév
                </label>
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-400 focus:border-transparent outline-none bg-gray-700/80 text-white placeholder-gray-300"
                  placeholder="Felhasználónév"
                  required
                />
              </div>
              <div className="mb-6">
                <label htmlFor="password" className="block text-sm font-medium text-white mb-2">
                  Jelszó
                </label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-400 focus:border-transparent outline-none bg-gray-700/80 text-white placeholder-gray-300"
                  required
                />
              </div>
              
              {loginError && (
                <div className="mb-4 p-3 bg-red-900/40 backdrop-blur-sm border border-red-500/50 text-red-200 rounded">
                  {loginError}
                </div>
              )}
              
              <button
                type="submit"
                className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Bejelentkezés
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 px-4 pb-20" 
         style={{
           backgroundImage: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)',
           backgroundSize: 'cover',
           backgroundRepeat: 'no-repeat',
           backgroundPosition: 'center'
         }}>
      <div className="absolute inset-0 backdrop-blur-sm"></div>
      <div className="max-w-7xl mx-auto relative z-10">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 sm:mb-8 pt-6 sm:pt-8 gap-4">
          <div className="flex-1 min-w-0">
            <h1 className="text-2xl sm:text-3xl font-bold text-white drop-shadow-lg break-words"> Prom - Admin</h1>
            <p className="text-white/70 mt-2 text-sm sm:text-base break-words">Bejelentkezve: {currentUser?.username} ({currentUser?.role === 'owner' ? 'Tulajdonos' : 'Admin'})</p>
          </div>
          <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
            {spotifyAccessToken ? (
              <button
                onClick={handleSpotifyLogout}
                className="bg-green-600 hover:bg-green-700 text-white px-4 py-3 sm:py-2 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
              >
                <FontAwesomeIcon icon={faSpotify} />
                {spotifyUser?.name} - Kijelentkezés
              </button>
            ) : (
              <button
                onClick={handleSpotifyAuth}
                className="bg-green-600 hover:bg-green-700 text-white px-4 py-3 sm:py-2 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
              >
                <FontAwesomeIcon icon={faSpotify} />
                Spotify Bejelentkezés
              </button>
            )}
            {currentUser?.role === 'owner' && (
              <>
                <button
                  onClick={() => setShowSettings(!showSettings)}
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-3 sm:py-2 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
                >
                  <FontAwesomeIcon icon={faCog} />
                  Beállítások
                </button>
                <button
                  onClick={() => setShowUserManagement(!showUserManagement)}
                  className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-3 sm:py-2 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
                >
                  <FontAwesomeIcon icon={faTrash} />
                  Felhasználók
                </button>
                <button
                  onClick={() => setShowAnalytics(!showAnalytics)}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-3 sm:py-2 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
                >
                  <FontAwesomeIcon icon={faMusic} />
                  Analitika
                </button>
              </>
            )}
            <button
              onClick={handleLogout}
              className="bg-red-500 text-white px-4 py-3 sm:py-2 rounded-lg hover:bg-red-600 transition-colors flex items-center justify-center gap-2 text-sm font-medium min-h-[44px] sm:min-h-0"
            >
              <FontAwesomeIcon icon={faSignOutAlt} />
              Kilépés
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <>
            <div className="bg-gray-800/80 backdrop-blur-xl rounded-2xl shadow-2xl mb-6 p-4 sm:p-6 border border-gray-600/50">
              <h2 className="text-xl sm:text-2xl font-bold mb-4 sm:mb-6 text-white drop-shadow-lg">Statisztikák</h2>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="text-center bg-gray-700/40 p-4 rounded-xl">
                  <div className="text-2xl sm:text-3xl font-bold text-blue-300 drop-shadow-lg">
                    {submissions.length}
                  </div>
                  <div className="text-white/80 font-medium text-sm sm:text-base">Összes Szám</div>
                </div>
                <div className="text-center bg-gray-700/40 p-4 rounded-xl">
                  <div className="text-2xl sm:text-3xl font-bold text-blue-300 drop-shadow-lg">
                    {submissions.reduce((sum, sub) => sum + sub.count, 0)}
                  </div>
                  <div className="text-white/80 font-medium text-sm sm:text-base">Összes Beküldés</div>
                </div>
                <div className="text-center bg-gray-700/40 p-4 rounded-xl">
                  <div className="text-2xl sm:text-3xl font-bold text-blue-300 drop-shadow-lg">
                    {submissions.length > 0 ? Math.max(...submissions.map(sub => sub.count)) : 0}
                  </div>
                  <div className="text-white/80 font-medium text-sm sm:text-base">Legtöbb Beküldés</div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800/80 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50">
              <div className="px-4 sm:px-6 py-4 border-b border-gray-600/50 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <h2 className="text-xl sm:text-2xl font-bold text-white drop-shadow-lg">Beküldött Számok</h2>
                <div className="flex items-center gap-4 w-full sm:w-auto">
                  <button
                    onClick={() => {
                      setModalType('submissions');
                      setShowModal(true);
                    }}
                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 sm:px-6 py-3 rounded-lg transition-colors flex items-center justify-center gap-2 font-semibold text-sm w-full sm:w-auto min-h-[44px]"
                  >
                    <FontAwesomeIcon icon={faExpand} className="text-lg" />
                    Nagyítás
                  </button>
                </div>
              </div>
              
              {sortedSubmissions.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  Még nincsenek beküldések
                </div>
              ) : (
                <div className="max-h-96 overflow-y-auto overflow-x-auto custom-scrollbar">
                  <table className="w-full">
                    <thead className="bg-gray-700/90 backdrop-blur-sm sticky top-0 z-10">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                          Szám
                        </th>
                        <th 
                          className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600/50 transition-colors"
                          onClick={() => handleSort('count')}
                        >
                          Darabszám {getSortIcon('count')}
                        </th>
                        <th 
                          className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600/50 transition-colors"
                          onClick={() => handleSort('firstSubmittedAt')}
                        >
                          Első Beküldés {getSortIcon('firstSubmittedAt')}
                        </th>
                        <th 
                          className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600/50 transition-colors"
                          onClick={() => handleSort('lastSubmittedAt')}
                        >
                          Utolsó Beküldés {getSortIcon('lastSubmittedAt')}
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                          Platform
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                          Műveletek
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-gray-800/40 divide-y divide-gray-600/50">
                      {sortedSubmissions.map((submission) => (
                        <tr key={submission.id} className="hover:bg-gray-700/50 transition-colors">
                          <td className="px-6 py-4">
                            <div className="flex items-center">
                              {submission.thumbnail && (
                                <img
                                  className="h-12 w-12 rounded-lg mr-4"
                                  src={submission.thumbnail}
                                  alt={submission.title}
                                />
                              )}
                              <div>
                                <div className="flex items-center gap-2 text-sm font-medium text-white">
                                  {submission.title}
                                  {(submission.explicit === true || (submission.explicit as any) === 'true' || (submission.explicit as any) === 1) && (
                                    <span className="text-red-400 text-xs" title="Explicit content">
                                      <FontAwesomeIcon icon={faExclamationTriangle} />
                                    </span>
                                  )}
                                </div>
                                <div className="text-sm text-white/70">
                                  {submission.artist} által
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                              {submission.count}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                            {formatDate(submission.firstSubmittedAt)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                            {formatDate(submission.lastSubmittedAt)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              {submission.platform === 'spotify' ? (
                                <div className="flex items-center gap-1 px-2 py-1 bg-green-900/30 border border-green-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faSpotify} className="text-green-400 text-xs" />
                                  <span className="text-green-300 text-xs font-medium">Spotify</span>
                                </div>
                              ) : submission.platform === 'deezer' ? (
                                <div className="flex items-center gap-1 px-2 py-1 bg-orange-900/30 border border-orange-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faMusic} className="text-orange-400 text-xs" />
                                  <span className="text-orange-300 text-xs font-medium">Deezer</span>
                                </div>
                              ) : (
                                <div className="flex items-center gap-1 px-2 py-1 bg-gray-900/30 border border-gray-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faMusic} className="text-gray-400 text-xs" />
                                  <span className="text-gray-400 text-xs font-medium">Ismeretlen</span>
                                </div>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center gap-2">
                              <a
                                href={submission.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1"
                              >
                                <FontAwesomeIcon icon={faMusic} />
                                Megtekintés
                              </a>
                              <button
                                onClick={() => handleAddToSpotify(submission.title, submission.artist)}
                                className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1"
                              >
                                <FontAwesomeIcon icon={faSpotify} />
                                Spotify
                              </button>
                              <button
                                onClick={() => handleDelete(submission.id)}
                                className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 transition-colors px-3 py-1 rounded bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 flex items-center gap-2"
                              >
                                <FontAwesomeIcon icon={faTrash} />
                                Törlés
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>



            {submissions.length > 0 && (
              <div className="mt-6 bg-gray-800/80 backdrop-blur-xl rounded-2xl shadow-2xl p-4 sm:p-6 border border-gray-600/50">
                <h3 className="text-lg sm:text-xl font-bold mb-4 sm:mb-6 text-white drop-shadow-lg">Top 5 Leggyakrabban Beküldött Szám</h3>
                <div className="space-y-2">
                  {submissions
                    .sort((a, b) => b.count - a.count)
                    .slice(0, 5)
                    .map((track, index) => (
                      <div key={track.id} className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 sm:p-4 bg-gray-700/60 backdrop-blur-sm rounded-xl border border-gray-600/50 hover:bg-gray-600/60 transition-colors  gap-3">
                        <div className="flex items-center w-full sm:w-auto">
                          <span className="text-lg sm:text-xl font-bold text-blue-300 drop-shadow-lg mr-3 sm:mr-4 flex-shrink-0">
                            #{index + 1}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="font-semibold text-white text-sm sm:text-base break-words">{track.title}</div>
                            <div className="text-xs sm:text-sm text-white/70 break-words">{track.artist} által</div>
                          </div>
                        </div>
                        <span className="bg-gradient-to-r from-blue-500 to-purple-600 text-white px-3 sm:px-4 py-2 rounded-full text-xs sm:text-sm font-medium shadow-lg flex-shrink-0 w-full sm:w-auto text-center">
                          {track.count} beküldés
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Logok megjelenítése - csak mate felhasználónak - mindig látható */}
            {currentUser?.role === 'owner' && (
              <div className="mt-6 bg-gray-800/80 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50">
                <div className="px-4 sm:px-6 py-4 border-b border-gray-600/50 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <h3 className="text-lg sm:text-xl font-bold text-white drop-shadow-lg">Felhasználói Logok</h3>
                  <button
                    onClick={() => {
                      setModalType('logs');
                      setShowModal(true);
                    }}
                    className="bg-green-600 hover:bg-green-700 text-white px-4 sm:px-6 py-3 rounded-lg transition-colors flex items-center justify-center gap-2 font-semibold text-sm w-full sm:w-auto min-h-[44px]"
                  >
                    <FontAwesomeIcon icon={faExpand} className="text-lg" />
                    Nagyítás
                  </button>
                </div>
                
                {logsLoading ? (
                  <div className="flex justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                  </div>
                ) : (
                  <div className="max-h-96 overflow-y-auto p-4 sm:p-6 custom-scrollbar ">
                    {logs.length === 0 ? (
                      <p className="text-gray-400 text-center py-8">Nincsenek logok</p>
                    ) : (
                      <div className="space-y-3">
                        {logs.map((log) => (
                          <div key={log.id} className="p-3 sm:p-4 bg-gray-700/60 backdrop-blur-sm rounded-xl border border-gray-600/50 hover:bg-gray-600/60 transition-colors ">
                            <div className="flex flex-col sm:flex-row justify-between items-start mb-2 gap-2">
                              <div className="break-words">
                                <span className="font-semibold text-blue-300 text-sm sm:text-base">{log.username}</span>
                                <span className="mx-2 text-white/50">•</span>
                                <span className="text-white text-sm sm:text-base">{getActionTypeText(log.action_type)}</span>
                              </div>
                              <span className="text-xs text-white/60 bg-gray-800/50 px-2 py-1 rounded flex-shrink-0">{formatLogDate(log.created_at)}</span>
                            </div>
                            {log.description && (
                              <p className="text-white/80 text-xs sm:text-sm mb-2 break-words bg-gray-800/30 p-2 rounded">{log.description}</p>
                            )}
                            {(log.track_title || log.track_artist) && (
                              <div className="text-xs text-white/70 mb-2 bg-purple-900/20 p-2 rounded border border-purple-500/20">
                                <span className="font-medium">Zeneszám:</span> {log.track_title} - {log.track_artist}
                              </div>
                            )}
                            <div className="flex flex-col sm:flex-row gap-2 sm:gap-4 text-xs text-white/60">
                              <span className="break-all"><strong>IP:</strong> {log.ip_address}</span>
                              {log.user_agent && (
                                <span className="break-all"><strong>Böngésző:</strong> {log.user_agent.substring(0, 30)}...</span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Modal komponens */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-start sm:items-center justify-center p-2 sm:p-4 bg-black/80 backdrop-blur-sm">
            <div className="bg-gray-800/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50 w-full max-w-[95vw] h-[98vh] sm:h-[90vh] flex flex-col mt-2 sm:mt-0">
              {/* Modal Header */}
              <div className="px-4 sm:px-8 py-4 sm:py-6 border-b border-gray-600/50 flex flex-col justify-between gap-4">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  <h2 className="text-xl sm:text-3xl font-bold text-white drop-shadow-lg break-words">
                    {modalType === 'submissions'
                      ? searchQuery
                        ? `Beküldött Számok (${sortedSubmissions.length}/${submissions.length})`
                        : `Összes Beküldött Szám (${submissions.length})`
                      : `Felhasználói Logok (${logs.length})`
                    }
                  </h2>
                  <button
                    onClick={() => setShowModal(false)}
                    className="bg-red-600 hover:bg-red-700 active:bg-red-800 text-white px-4 sm:px-6 py-3 rounded-xl transition-colors flex items-center gap-2 text-base sm:text-lg font-semibold min-h-[48px] w-full sm:w-auto justify-center shadow-lg"
                  >
                    <FontAwesomeIcon icon={faTimes} />
                    Bezár
                  </button>
                </div>
                
                {/* Rendezési gombok - csak submissions modal-ban */}
                {modalType === 'submissions' && (
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => handleSort('count')}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        sortBy === 'count' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Beküldések {sortBy === 'count' && (sortOrder === 'DESC' ? '(nagy→kis)' : '(kis→nagy)')}
                    </button>
                    <button
                      onClick={() => handleSort('lastSubmittedAt')}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        sortBy === 'lastSubmittedAt' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Dátum {sortBy === 'lastSubmittedAt' && (sortOrder === 'DESC' ? '(új→régi)' : '(régi→új)')}
                    </button>
                    <button
                      onClick={() => handleSort('title')}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        sortBy === 'title' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Cím {sortBy === 'title' && (sortOrder === 'DESC' ? '(Z→A)' : '(A→Z)')}
                    </button>
                    <button
                      onClick={() => handleSort('rating')}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        sortBy === 'rating' 
                          ? 'bg-blue-600 text-white' 
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Értékelés {sortBy === 'rating' && (sortOrder === 'DESC' ? '(legjobb→legrosszabb)' : '(legrosszabb→legjobb)')}
                    </button>
                  </div>
                )}

                {/* Keresési mező - csak submissions modal-ban */}
                {modalType === 'submissions' && (
                  <div className="mt-4">
                    <div className="relative">
                      <input
                        type="text"
                        placeholder="Keresés cím, előadó vagy platform alapján..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                      />
                      {searchQuery && (
                        <button
                          onClick={() => setSearchQuery('')}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                        >
                          <FontAwesomeIcon icon={faTimes} />
                        </button>
                      )}
                    </div>
                    {searchQuery && (
                      <div className="mt-2 text-sm text-gray-400">
                        {sortedSubmissions.length} találat a(z) "{searchQuery}" keresésre
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-auto p-3 sm:p-6 custom-scrollbar">
                {modalType === 'submissions' ? (
                  submissions.length === 0 ? (
                    <div className="text-center py-12 text-gray-400 text-lg sm:text-xl">
                      Még nincsenek beküldések
                    </div>
                  ) : (
                    <div className="space-y-3 sm:space-y-4">
                      {/* Desktop fejléc - csak nagy képernyőn */}
                      <div className="hidden lg:flex text-sm font-medium text-gray-400 mb-4 px-4 border-b border-gray-600 pb-2">
                        <span className="flex-1">SZÁM</span>
                        <span className="w-20 text-center">DARABSZÁM</span>
                        <span className="w-32 text-center">UTOLSÓ BEKÜLDÉS</span>
                        <span className="w-24 text-center">PLATFORM</span>
                        <span className="w-32 text-center">RATING</span>
                        <span className="w-32 text-center">MEGTEKINTÉS</span>
                        <span className="w-32 text-center">SPOTIFY</span>
                        <span className="w-20 text-center">TÖRLÉS</span>
                      </div>
                      {sortedSubmissions.map((submission) => (
                        <div key={submission.id} className="bg-gray-700/40 rounded-lg sm:rounded-xl p-3 sm:p-4 shadow-lg">
                          {/* Desktop layout */}
                          <div className="hidden lg:flex items-center">
                            <div className="flex-1 flex items-center min-w-0">
                              {submission.thumbnail && (
                                <img
                                  className="h-12 w-12 rounded-lg mr-4 flex-shrink-0"
                                  src={submission.thumbnail}
                                  alt={submission.title}
                                />
                              )}
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2 text-base font-medium text-white truncate">
                                  {submission.title}
                                  {(submission.explicit === true || (submission.explicit as any) === 'true' || (submission.explicit as any) === 1) && (
                                    <span className="text-red-400 text-sm" title="Explicit content">
                                      <FontAwesomeIcon icon={faExclamationTriangle} />
                                    </span>
                                  )}
                                </div>
                                <div className="text-sm text-white/70 truncate">
                                  {submission.artist}
                                </div>
                              </div>
                            </div>
                            <div className="w-20 text-center">
                              <span className="bg-green-500 text-white px-3 py-1 rounded-full text-sm font-semibold">
                                {submission.count}
                              </span>
                            </div>
                            <div className="w-32 text-center text-sm text-gray-300">
                              {formatDate(submission.lastSubmittedAt)}
                            </div>
                            <div className="w-24 text-center">
                              {submission.platform === 'spotify' ? (
                                <div className="inline-flex items-center gap-1 px-2 py-1 bg-green-900/30 border border-green-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faSpotify} className="text-green-400 text-xs" />
                                  <span className="text-green-300 text-xs font-medium">Spotify</span>
                                </div>
                              ) : submission.platform === 'deezer' ? (
                                <div className="inline-flex items-center gap-1 px-2 py-1 bg-orange-900/30 border border-orange-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faMusic} className="text-orange-400 text-xs" />
                                  <span className="text-orange-300 text-xs font-medium">Deezer</span>
                                </div>
                              ) : (
                                <div className="inline-flex items-center gap-1 px-2 py-1 bg-gray-900/30 border border-gray-500/50 rounded-full">
                                  <FontAwesomeIcon icon={faMusic} className="text-gray-400 text-xs" />
                                  <span className="text-gray-400 text-xs font-medium">N/A</span>
                                </div>
                              )}
                            </div>
                            <div className="w-32 text-center">
                              <div className="flex items-center justify-center gap-1">
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'ok' ? null : 'ok')}
                                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                                    submission.rating === 'ok' 
                                      ? 'bg-green-600 text-white' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Jó"
                                >
                                  <FontAwesomeIcon icon={faThumbsUp} />
                                </button>
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'bad' ? null : 'bad')}
                                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                                    submission.rating === 'bad' 
                                      ? 'bg-red-600 text-white' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Rossz"
                                >
                                  <FontAwesomeIcon icon={faThumbsDown} />
                                </button>
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'middle' ? null : 'middle')}
                                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                                    submission.rating === 'middle' 
                                      ? 'bg-orange-600 text-white' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Közepes"
                                >
                                  <FontAwesomeIcon icon={faExclamationCircle} />
                                </button>
                              </div>
                            </div>
                            <div className="w-32 text-center">
                              <a
                                href={submission.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="bg-blue-600 text-white px-3 py-1 rounded text-sm font-medium inline-flex items-center gap-1 hover:bg-blue-700"
                              >
                                <FontAwesomeIcon icon={faMusic} className="text-xs" />
                                Megtekintés
                              </a>
                            </div>
                            <div className="w-32 text-center">
                              <button
                                onClick={() => handleAddToSpotify(submission.title, submission.artist)}
                                className="bg-green-600 text-white px-3 py-1 rounded text-sm font-medium inline-flex items-center gap-1 hover:bg-green-700"
                              >
                                <FontAwesomeIcon icon={faSpotify} className="text-xs" />
                                Spotify
                              </button>
                            </div>
                            <div className="w-20 text-center">
                              <button
                                onClick={() => handleDelete(submission.id)}
                                className="text-red-400 p-2 rounded"
                                title="Törlés"
                              >
                                <FontAwesomeIcon icon={faTrash} />
                              </button>
                            </div>
                          </div>
                          
                          {/* Mobile layout */}
                          <div className="lg:hidden space-y-4">
                            {/* Kép és cím */}
                            <div className="flex items-center gap-4">
                              {submission.thumbnail && (
                                <img
                                  className="h-20 w-20 rounded-xl flex-shrink-0 shadow-lg"
                                  src={submission.thumbnail}
                                  alt={submission.title}
                                />
                              )}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 text-lg font-semibold text-white break-words leading-snug mb-1">
                                  {submission.title}
                                  {(submission.explicit === true || (submission.explicit as any) === 'true' || (submission.explicit as any) === 1) && (
                                    <span className="text-red-400 text-sm" title="Explicit content">
                                      <FontAwesomeIcon icon={faExclamationTriangle} />
                                    </span>
                                  )}
                                </div>
                                <div className="text-base text-white/80 break-words">
                                  {submission.artist}
                                </div>
                              </div>
                            </div>
                            
                            {/* Info sáv */}
                            <div className="flex items-center gap-4 bg-gray-800/60 rounded-xl p-4">
                              <div className="text-center">
                                <div className="text-sm text-gray-300 mb-2 font-medium">Beküldések</div>
                                <span className="bg-green-500 text-white px-3 py-2 rounded-full text-base font-bold">
                                  {submission.count}
                                </span>
                              </div>
                              <div className="flex-1 text-center px-3">
                                <div className="text-sm text-gray-300 mb-2 font-medium">Utolsó beküldés</div>
                                <div className="text-sm text-white/90 leading-tight">
                                  {formatDate(submission.lastSubmittedAt)}
                                </div>
                              </div>
                              <div className="text-center">
                                <div className="text-sm text-gray-300 mb-2 font-medium">Platform</div>
                                <div className="flex justify-center">
                                  {submission.platform === 'spotify' ? (
                                    <div className="flex items-center gap-1 px-2 py-1 bg-green-900/50 border border-green-500/50 rounded-full">
                                      <FontAwesomeIcon icon={faSpotify} className="text-green-400 text-xs" />
                                      <span className="text-green-300 text-xs font-medium">Spotify</span>
                                    </div>
                                  ) : submission.platform === 'deezer' ? (
                                    <div className="flex items-center gap-1 px-2 py-1 bg-orange-900/50 border border-orange-500/50 rounded-full">
                                      <FontAwesomeIcon icon={faMusic} className="text-orange-400 text-xs" />
                                      <span className="text-orange-300 text-xs font-medium">Deezer</span>
                                    </div>
                                  ) : (
                                    <div className="flex items-center gap-1 px-2 py-1 bg-gray-900/50 border border-gray-500/50 rounded-full">
                                      <FontAwesomeIcon icon={faMusic} className="text-gray-400 text-xs" />
                                      <span className="text-gray-400 text-xs font-medium">N/A</span>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                            
                            {/* Rating sáv */}
                            <div className="bg-gray-800/60 rounded-xl p-4">
                              <div className="text-sm text-gray-300 mb-3 font-medium text-center">Értékelés</div>
                              <div className="flex items-center justify-center gap-3">
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'ok' ? null : 'ok')}
                                  className={`px-4 py-3 rounded-xl text-lg font-medium transition-colors min-w-[60px] ${
                                    submission.rating === 'ok' 
                                      ? 'bg-green-600 text-white shadow-lg' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Jó"
                                >
                                  <FontAwesomeIcon icon={faThumbsUp} />
                                </button>
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'bad' ? null : 'bad')}
                                  className={`px-4 py-3 rounded-xl text-lg font-medium transition-colors min-w-[60px] ${
                                    submission.rating === 'bad' 
                                      ? 'bg-red-600 text-white shadow-lg' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Rossz"
                                >
                                  <FontAwesomeIcon icon={faThumbsDown} />
                                </button>
                                <button
                                  onClick={() => handleRating(submission.id, submission.rating === 'middle' ? null : 'middle')}
                                  className={`px-4 py-3 rounded-xl text-lg font-medium transition-colors min-w-[60px] ${
                                    submission.rating === 'middle' 
                                      ? 'bg-orange-600 text-white shadow-lg' 
                                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                                  }`}
                                  title="Közepes"
                                >
                                  <FontAwesomeIcon icon={faExclamationCircle} />
                                </button>
                              </div>
                            </div>
                            
                            {/* Műveletek */}
                            <div className="flex flex-col sm:flex-row gap-3">
                              <a
                                href={submission.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex-1 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white py-4 rounded-xl text-base font-semibold flex items-center justify-center gap-3 min-h-[52px] shadow-lg transition-all"
                              >
                                <FontAwesomeIcon icon={faMusic} className="text-lg" />
                                Megtekintés
                              </a>
                              <button
                                onClick={() => handleAddToSpotify(submission.title, submission.artist)}
                                className="flex-1 bg-green-600 hover:bg-green-700 active:bg-green-800 text-white py-4 rounded-xl text-base font-semibold flex items-center justify-center gap-3 min-h-[52px] shadow-lg transition-all"
                              >
                                <FontAwesomeIcon icon={faSpotify} className="text-lg" />
                                Spotify Lista
                              </button>
                              <button
                                onClick={() => handleDelete(submission.id)}
                                className="sm:w-auto w-full bg-red-600 hover:bg-red-700 active:bg-red-800 text-white px-6 py-4 rounded-xl text-base font-semibold flex items-center justify-center gap-3 min-h-[52px] shadow-lg transition-all"
                              >
                                <FontAwesomeIcon icon={faTrash} className="text-lg" />
                                Törlés
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                ) : (
                  logs.length === 0 ? (
                    <div className="text-center py-12 text-gray-400 text-xl">
                      Nincsenek logok
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                      {logs.map((log) => (
                        <div
                          key={log.id}
                          className="bg-gray-700/60 rounded-xl p-6 border border-gray-600/50"
                        >
                          {/* Log header */}
                          <div className="flex justify-between items-start mb-3">
                            <div>
                              <span className="font-bold text-blue-300 text-lg">{log.username}</span>
                              <span className="mx-2 text-white/50">•</span>
                              <span className="text-white font-medium">{getActionTypeText(log.action_type)}</span>
                            </div>
                            <span className="text-xs text-white/60 bg-gray-800/50 px-2 py-1 rounded">
                              {formatLogDate(log.created_at)}
                            </span>
                          </div>
                          
                          {/* Log description */}
                          {log.description && (
                            <p className="text-white/80 text-sm mb-3 bg-gray-800/30 p-3 rounded-lg">
                              {log.description}
                            </p>
                          )}
                          
                          {/* Track info if available */}
                          {(log.track_title || log.track_artist) && (
                            <div className="mb-3 p-3 bg-purple-900/20 rounded-lg border border-purple-500/20">
                              <div className="text-xs text-purple-300 font-medium mb-1">Zeneszám:</div>
                              <div className="text-sm text-white">{log.track_title}</div>
                              <div className="text-xs text-white/70">{log.track_artist} által</div>
                            </div>
                          )}
                          
                          {/* Technical info */}
                          <div className="space-y-2 text-xs">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-green-300">IP:</span>
                              <span className="text-white bg-gray-800/50 px-2 py-1 rounded font-mono">
                                {log.ip_address}
                              </span>
                            </div>
                            {log.user_agent && (
                              <div>
                                <span className="font-medium text-blue-300">Böngésző:</span>
                                <div className="text-white/70 mt-1 p-2 bg-gray-800/30 rounded text-xs break-all">
                                  {log.user_agent}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                )}
              </div>
              
              {/* Modal Footer */}
              <div className="px-4 sm:px-8 py-3 sm:py-4 border-t border-gray-600/50 bg-gray-800/90">
                <div className="flex flex-col sm:flex-row justify-between items-center text-white/70 text-xs sm:text-sm gap-2 sm:gap-0">
                  {modalType === 'submissions' ? (
                    <>
                      <span className="text-center sm:text-left">
                        {searchQuery
                          ? `${sortedSubmissions.length} / ${submissions.length} zeneszám`
                          : `Összesen ${submissions.length} zeneszám`
                        }
                      </span>
                      <span className="text-center sm:text-right">
                        {searchQuery
                          ? `Szűrt beküldések: ${sortedSubmissions.reduce((sum, sub) => sum + sub.count, 0)} / ${submissions.reduce((sum, sub) => sum + sub.count, 0)}`
                          : `Összes beküldés: ${submissions.reduce((sum, sub) => sum + sub.count, 0)}`
                        }
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="text-center sm:text-left">Összesen {logs.length} log bejegyzés</span>
                      <span className="text-center sm:text-right">Utolsó frissítés: {logs.length > 0 ? formatLogDate(logs[0]?.created_at) : 'Nincs'}</span>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* User Management Modal */}
        {showUserManagement && currentUser?.role === 'owner' && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="bg-gray-800/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50 w-full max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
              {/* Modal Header */}
              <div className="px-6 py-4 border-b border-gray-600/50 flex justify-between items-center">
                <h2 className="text-2xl font-bold text-white">Felhasználó Kezelés</h2>
                <button
                  onClick={() => setShowUserManagement(false)}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
                >
                  <FontAwesomeIcon icon={faTimes} />
                  Bezár
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-auto p-6 space-y-6 custom-scrollbar ">
                {/* Create New User Section */}
                <div>
                  <h3 className="text-xl font-semibold text-white mb-4">Új Admin Felhasználó Létrehozása</h3>
                  <div className="bg-gray-700/60 p-4 rounded-lg">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <input
                        type="text"
                        placeholder="Felhasználónév (minimum 3 karakter)"
                        className="px-3 py-2 bg-gray-600 text-white rounded-lg focus:ring-2 focus:ring-blue-400 outline-none"
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') {
                            const username = (e.target as HTMLInputElement).value;
                            const passwordInput = (e.target as HTMLElement).parentElement?.querySelector('input[type="password"]') as HTMLInputElement;
                            const password = passwordInput?.value || '';
                            handleCreateUser(username, password).then(success => {
                              if (success) {
                                (e.target as HTMLInputElement).value = '';
                                if (passwordInput) passwordInput.value = '';
                              }
                            });
                          }
                        }}
                      />
                      <input
                        type="password"
                        placeholder="Jelszó (minimum 4 karakter)"
                        className="px-3 py-2 bg-gray-600 text-white rounded-lg focus:ring-2 focus:ring-blue-400 outline-none"
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') {
                            const password = (e.target as HTMLInputElement).value;
                            const usernameInput = (e.target as HTMLElement).parentElement?.querySelector('input[type="text"]') as HTMLInputElement;
                            const username = usernameInput?.value || '';
                            handleCreateUser(username, password).then(success => {
                              if (success) {
                                (e.target as HTMLInputElement).value = '';
                                if (usernameInput) usernameInput.value = '';
                              }
                            });
                          }
                        }}
                      />
                    </div>
                    <button
                      onClick={(e) => {
                        const inputs = (e.target as HTMLElement).parentElement?.querySelectorAll('input') as NodeListOf<HTMLInputElement>;
                        const username = inputs[0]?.value || '';
                        const password = inputs[1]?.value || '';
                        handleCreateUser(username, password).then(success => {
                          if (success) {
                            inputs[0].value = '';
                            inputs[1].value = '';
                          }
                        });
                      }}
                      disabled={userActionLoading}
                      className="w-full mt-3 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {userActionLoading ? 'Létrehozás...' : 'Admin Létrehozása'}
                    </button>
                  </div>
                </div>

                {/* Existing Users Section */}
                <div>
                  <h3 className="text-xl font-semibold text-white mb-4">Meglévő Felhasználók</h3>
                  {usersLoading ? (
                    <div className="flex justify-center py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {allUsers.map((user: any) => (
                        <div key={user.id} className="bg-gray-700/60 p-4 rounded-lg">
                          <div className="flex justify-between items-center mb-3">
                            <div className="flex items-center gap-3">
                              <span className="font-semibold text-white">{user.username}</span>
                              <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                                user.role === 'owner' 
                                  ? 'bg-yellow-500 text-black' 
                                  : 'bg-blue-500 text-white'
                              }`}>
                                {user.role === 'owner' ? 'Tulajdonos' : 'Admin'}
                              </span>
                              <span className="text-xs text-gray-400">
                                Létrehozva: {new Date(user.created_at).toLocaleDateString('hu-HU')}
                              </span>
                            </div>
                            {user.role !== 'owner' && (
                              <button
                                onClick={() => handleDeleteUser(user.username)}
                                disabled={userActionLoading}
                                className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded-lg transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                Törlés
                              </button>
                            )}
                          </div>
                          
                          {/* Password change row */}
                          <div className="flex gap-2 mb-2">
                            <input
                              type="password"
                              placeholder="Új jelszó (minimum 4 karakter)"
                              className="flex-1 px-3 py-2 bg-gray-600 text-white rounded-lg focus:ring-2 focus:ring-purple-400 outline-none"
                              onKeyPress={(e) => {
                                if (e.key === 'Enter') {
                                  const password = (e.target as HTMLInputElement).value;
                                  handlePasswordChange(user.username, password).then(success => {
                                    if (success) (e.target as HTMLInputElement).value = '';
                                  });
                                }
                              }}
                            />
                            <button
                              onClick={(e) => {
                                const input = (e.target as HTMLElement).parentElement?.querySelector('input[type="password"]') as HTMLInputElement;
                                const password = input.value;
                                handlePasswordChange(user.username, password).then(success => {
                                  if (success) input.value = '';
                                });
                              }}
                              disabled={passwordChangeLoading}
                              className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                              Jelszó
                            </button>
                          </div>
                          
                          {/* Username change row */}
                          {user.role !== 'owner' && (
                            <div className="flex gap-2">
                              <input
                                type="text"
                                placeholder="Új felhasználónév"
                                className="flex-1 px-3 py-2 bg-gray-600 text-white rounded-lg focus:ring-2 focus:ring-orange-400 outline-none"
                                onKeyPress={(e) => {
                                  if (e.key === 'Enter') {
                                    const newUsername = (e.target as HTMLInputElement).value;
                                    handleRenameUser(user.username, newUsername).then(success => {
                                      if (success) (e.target as HTMLInputElement).value = '';
                                    });
                                  }
                                }}
                              />
                              <button
                                onClick={(e) => {
                                  const input = (e.target as HTMLElement).parentElement?.querySelector('input[type="text"]') as HTMLInputElement;
                                  const newUsername = input.value;
                                  handleRenameUser(user.username, newUsername).then(success => {
                                    if (success) input.value = '';
                                  });
                                }}
                                disabled={userActionLoading}
                                className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                Átnevez
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Settings Modal */}
        {showSettings && currentUser?.role === 'owner' && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="bg-gray-800/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50 w-full max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
              {/* Modal Header */}
              <div className="px-6 py-4 border-b border-gray-600/50 flex justify-between items-center">
                <h2 className="text-2xl font-bold text-white">Rendszer Beállítások</h2>
                <button
                  onClick={() => setShowSettings(false)}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
                >
                  <FontAwesomeIcon icon={faTimes} />
                  Bezár
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-auto p-6 space-y-6 custom-scrollbar">
                {settingsLoading ? (
                  <div className="flex justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {/* Site Mode Selector */}
                    <div className="bg-gray-700/60 p-6 rounded-lg">
                      <h3 className="text-xl font-semibold text-white mb-6">Oldal működési mód</h3>
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          {/* Normal Mode */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.site_mode || 'normal') === 'normal'
                              ? 'border-blue-500 bg-blue-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, site_mode: 'normal' }))}>
                            <div className="text-center">
                              <div className="text-3xl mb-2">🔍</div>
                              <h4 className="font-semibold text-white mb-2">Keresés mód</h4>
                              <p className="text-sm text-gray-300">Normál működés: keresés és beküldés engedélyezve</p>
                            </div>
                          </div>

                          {/* Maintenance Mode */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.site_mode || 'normal') === 'maintenance'
                              ? 'border-orange-500 bg-orange-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, site_mode: 'maintenance' }))}>
                            <div className="text-center">
                              <div className="text-3xl mb-2">🚧</div>
                              <h4 className="font-semibold text-white mb-2">Karbantartás mód</h4>
                              <p className="text-sm text-gray-300">Minden letiltva, csak karbantartási üzenet</p>
                            </div>
                          </div>

                          {/* What's Playing Mode */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.site_mode || 'normal') === 'whats_playing'
                              ? 'border-green-500 bg-green-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, site_mode: 'whats_playing' }))}>
                            <div className="text-center">
                              <div className="text-3xl mb-2">🎵</div>
                              <h4 className="font-semibold text-white mb-2">Mit hallgatok mód</h4>
                              <p className="text-sm text-gray-300">Keresés működik + "Mit hallgatok" megjelenítése</p>
                            </div>
                          </div>
                        </div>

                        {/* Message - Only show for maintenance or whats_playing mode */}
                        {((settingsValues.site_mode || 'normal') === 'maintenance' || (settingsValues.site_mode || 'normal') === 'whats_playing') && (
                          <div className="mt-6">
                            <label className="block text-sm font-medium text-white mb-2">
                              Üzenet {(settingsValues.site_mode || 'normal') === 'maintenance' ? '(karbantartás)' : '(bál közben)'}
                            </label>
                            <textarea
                              value={settingsValues.maintenance_message || ''}
                              onChange={(e) => setSettingsValues(prev => ({
                                ...prev,
                                maintenance_message: e.target.value
                              }))}
                              className="w-full px-3 py-2 bg-gray-600 text-white rounded-lg focus:ring-2 focus:ring-blue-400 outline-none resize-none"
                              rows={3}
                              placeholder={
                                (settingsValues.site_mode || 'normal') === 'maintenance' 
                                  ? "Karbantartási üzenet (pl. 'Az oldal jelenleg karbantartás alatt...')"
                                  : "Bál közben megjelenő üzenet (pl. 'Éppen a  Sulibál zajlik!')"
                              }
                            />
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Search API Configuration */}
                    <div className="bg-gray-700/40 rounded-xl p-6">
                      <h3 className="text-xl font-semibold text-white mb-6 flex items-center gap-3">
                        <FontAwesomeIcon icon={faMusic} className="text-blue-400" />
                        Keresési API beállítások
                      </h3>
                      
                      {/* Preferred Search API */}
                      <div className="mb-6">
                        <label className="block text-sm font-medium text-white mb-3">
                          Elsődleges keresési API
                        </label>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          {/* Auto Mode */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.preferred_search_api || 'auto') === 'auto'
                              ? 'border-blue-500 bg-blue-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, preferred_search_api: 'auto' }))}>
                            <div className="text-center">
                              <div className="text-2xl mb-2">🤖</div>
                              <h4 className="font-semibold text-white mb-2">Automatikus</h4>
                              <p className="text-xs text-gray-300">Spotify előnyben, Deezer tartalék</p>
                            </div>
                          </div>

                          {/* Spotify Only */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.preferred_search_api || 'auto') === 'spotify'
                              ? 'border-green-500 bg-green-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, preferred_search_api: 'spotify' }))}>
                            <div className="text-center">
                              <FontAwesomeIcon icon={faSpotify} className="text-2xl mb-2 text-green-500" />
                              <h4 className="font-semibold text-white mb-2">Csak Spotify</h4>
                              <p className="text-xs text-gray-300">Csak Spotify API használata</p>
                            </div>
                          </div>

                          {/* Deezer Only */}
                          <div className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            (settingsValues.preferred_search_api || 'auto') === 'deezer'
                              ? 'border-orange-500 bg-orange-900/30'
                              : 'border-gray-600 bg-gray-800/50 hover:border-gray-500'
                          }`}
                          onClick={() => setSettingsValues(prev => ({ ...prev, preferred_search_api: 'deezer' }))}>
                            <div className="text-center">
                              <div className="text-2xl mb-2">🎵</div>
                              <h4 className="font-semibold text-white mb-2">Csak Deezer</h4>
                              <p className="text-xs text-gray-300">Csak Deezer API használata</p>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Spotify API Enable/Disable Toggle */}
                      <div className="mb-4">
                        <label className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg cursor-pointer hover:bg-gray-800/70 transition-colors">
                          <div>
                            <span className="text-white font-medium">Spotify API engedélyezése</span>
                            <p className="text-sm text-gray-400">Ha kikapcsolva, csak Deezer API használható</p>
                          </div>
                          <input
                            type="checkbox"
                            checked={settingsValues.spotify_api_enabled === 'true'}
                            onChange={(e) => setSettingsValues(prev => ({
                              ...prev,
                              spotify_api_enabled: e.target.checked ? 'true' : 'false'
                            }))}
                            className="w-5 h-5 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                          />
                        </label>
                      </div>

                      {/* API Status Info */}
                      <div className="bg-gray-800/50 rounded-lg p-4">
                        <h4 className="font-medium text-white mb-3">API állapot információ</h4>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="text-gray-300">Spotify API:</span>
                            <span className={`font-medium px-2 py-1 rounded text-xs ${
                              settingsValues.spotify_api_enabled === 'true' 
                                ? 'bg-green-900/50 text-green-300' 
                                : 'bg-red-900/50 text-red-300'
                            }`}>
                              {settingsValues.spotify_api_enabled === 'true' ? 'Engedélyezve' : 'Letiltva'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-gray-300">Deezer API:</span>
                            <span className="font-medium px-2 py-1 rounded text-xs bg-green-900/50 text-green-300">
                              Mindig elérhető
                            </span>
                          </div>
                        </div>
                        
                        {(settingsValues.preferred_search_api || 'auto') === 'auto' && (
                          <div className="mt-3 p-3 bg-blue-900/30 border border-blue-500/50 rounded-lg">
                            <p className="text-xs text-blue-300">
                              <strong>Automatikus mód:</strong> A rendszer először Spotify-t próbál használni, 
                              ha az elérhető. Rate limit vagy hiba esetén automatikusan Deezer-re vált.
                            </p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Settings Preview */}
                    <div className="bg-gray-700/60 p-6 rounded-lg">
                      <h3 className="text-xl font-semibold text-white mb-4">Beállítások előnézete</h3>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                        <div className={`p-4 rounded-lg text-center ${
                          settingsValues.search_page_visible === 'true' 
                            ? 'bg-green-900/50 border border-green-500/50' 
                            : 'bg-red-900/50 border border-red-500/50'
                        }`}>
                          <div className="text-sm font-medium text-white mb-1">Keresőoldal</div>
                          <div className={`text-xs ${
                            settingsValues.search_page_visible === 'true' ? 'text-green-300' : 'text-red-300'
                          }`}>
                            {settingsValues.search_page_visible === 'true' ? 'Látható' : 'Rejtett'}
                          </div>
                        </div>
                        
                        <div className={`p-4 rounded-lg text-center ${
                          settingsValues.search_functionality_enabled === 'true' 
                            ? 'bg-green-900/50 border border-green-500/50' 
                            : 'bg-red-900/50 border border-red-500/50'
                        }`}>
                          <div className="text-sm font-medium text-white mb-1">Keresés</div>
                          <div className={`text-xs ${
                            settingsValues.search_functionality_enabled === 'true' ? 'text-green-300' : 'text-red-300'
                          }`}>
                            {settingsValues.search_functionality_enabled === 'true' ? 'Engedélyezve' : 'Letiltva'}
                          </div>
                        </div>
                        
                        <div className={`p-4 rounded-lg text-center ${
                          settingsValues.track_submission_enabled === 'true' 
                            ? 'bg-green-900/50 border border-green-500/50' 
                            : 'bg-red-900/50 border border-red-500/50'
                        }`}>
                          <div className="text-sm font-medium text-white mb-1">Beküldés</div>
                          <div className={`text-xs ${
                            settingsValues.track_submission_enabled === 'true' ? 'text-green-300' : 'text-red-300'
                          }`}>
                            {settingsValues.track_submission_enabled === 'true' ? 'Engedélyezve' : 'Letiltva'}
                          </div>
                        </div>
                      </div>

                      {/* API Settings Preview */}
                      <div className="border-t border-gray-600 pt-4 mt-4">
                        <h4 className="text-lg font-medium text-white mb-3">API Beállítások</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className={`p-4 rounded-lg text-center border ${
                            (settingsValues.preferred_search_api || 'auto') === 'auto'
                              ? 'bg-blue-900/50 border-blue-500/50'
                              : (settingsValues.preferred_search_api || 'auto') === 'spotify'
                              ? 'bg-green-900/50 border-green-500/50'
                              : 'bg-orange-900/50 border-orange-500/50'
                          }`}>
                            <div className="text-sm font-medium text-white mb-1">Keresési API</div>
                            <div className={`text-xs ${
                              (settingsValues.preferred_search_api || 'auto') === 'auto' 
                                ? 'text-blue-300' 
                                : (settingsValues.preferred_search_api || 'auto') === 'spotify'
                                ? 'text-green-300'
                                : 'text-orange-300'
                            }`}>
                              {(settingsValues.preferred_search_api || 'auto') === 'auto' && 'Automatikus'}
                              {(settingsValues.preferred_search_api || 'auto') === 'spotify' && 'Csak Spotify'}
                              {(settingsValues.preferred_search_api || 'auto') === 'deezer' && 'Csak Deezer'}
                            </div>
                          </div>

                          <div className={`p-4 rounded-lg text-center ${
                            settingsValues.spotify_api_enabled === 'true' 
                              ? 'bg-green-900/50 border border-green-500/50' 
                              : 'bg-red-900/50 border border-red-500/50'
                          }`}>
                            <div className="text-sm font-medium text-white mb-1">Spotify API</div>
                            <div className={`text-xs ${
                              settingsValues.spotify_api_enabled === 'true' ? 'text-green-300' : 'text-red-300'
                            }`}>
                              {settingsValues.spotify_api_enabled === 'true' ? 'Engedélyezve' : 'Letiltva'}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Admin Spotify Connection Section */}
                    <div className="bg-gray-700/40 rounded-xl p-6">
                      <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-3">
                        <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                          <FontAwesomeIcon icon={faSpotify} className="text-white text-sm" />
                        </div>
                        "Mit hallgatok" fiók kapcsolat
                      </h3>
                      <p className="text-gray-300 mb-6 text-sm">
                        Kapcsold össze a Spotify fiókodat, hogy a látogatók láthassák mit hallgatsz éppen.
                      </p>
                      
                      {adminSpotifyLoading ? (
                        <div className="flex items-center justify-center py-4">
                          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                          <span className="text-white ml-3">Ellenőrzés...</span>
                        </div>
                      ) : adminSpotifyConnected && adminSpotifyUser ? (
                        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
                          <div className="flex items-center gap-4 mb-4">
                            {adminSpotifyUser.image && (
                              <img 
                                src={adminSpotifyUser.image} 
                                alt={adminSpotifyUser.name}
                                className="w-12 h-12 rounded-full"
                              />
                            )}
                            <div>
                              <h4 className="text-white font-semibold">{adminSpotifyUser.name}</h4>
                              <p className="text-green-300 text-sm">{adminSpotifyUser.email}</p>
                            </div>
                          </div>
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2 text-green-300 text-sm">
                              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                              <span>Kapcsolat aktív</span>
                            </div>
                            <button
                              onClick={handleAdminSpotifyDisconnect}
                              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition-colors"
                            >
                              Kapcsolat megszakítása
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-gray-300 text-sm mb-1">Nincs összekapcsolva</p>
                              <p className="text-gray-500 text-xs">
                                Kapcsold össze a fiókodat a "Mit hallgatok" funkcióhoz
                              </p>
                            </div>
                            <button
                              onClick={handleAdminSpotifyConnect}
                              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-2"
                            >
                              <FontAwesomeIcon icon={faSpotify} />
                              Kapcsolat létrehozása
                            </button>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Save Button */}
                    <div className="flex justify-center">
                      <button
                        onClick={handleSettingsUpdate}
                        disabled={settingsLoading}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg transition-colors font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {settingsLoading ? 'Mentés...' : 'Beállítások Mentése'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
        
        {/* Confirmation Modal */}
        {showConfirmation && confirmationData && (
          <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
            <div className="bg-gray-800/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50 w-full max-w-md">
              <div className="p-6">
                <h3 className="text-xl font-bold text-white mb-4">Megerősítés</h3>
                <p className="text-white/80 mb-6">{confirmationData.message}</p>
                <div className="flex gap-3">
                  <button
                    onClick={handleCancel}
                    className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded-lg transition-colors font-medium"
                  >
                    Mégse
                  </button>
                  <button
                    onClick={handleConfirm}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-lg transition-colors font-medium"
                  >
                    Igen, törlés
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Analytics Modal */}
        {showAnalytics && currentUser?.role === 'owner' && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="bg-gray-800/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-600/50 w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
              {/* Modal Header */}
              <div className="px-6 py-4 border-b border-gray-600/50 flex justify-between items-center">
                <h2 className="text-2xl font-bold text-white">Platform Analitika és API Statisztikák</h2>
                <button
                  onClick={() => setShowAnalytics(false)}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
                >
                  <FontAwesomeIcon icon={faTimes} />
                  Bezár
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-auto p-6 custom-scrollbar">
                {analyticsLoading ? (
                  <div className="flex justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                  </div>
                ) : analyticsData && apiUsageStats ? (
                  <div className="space-y-6">
                    
                    {/* API Status Overview */}
                    <div className="bg-gray-700/40 rounded-xl p-6">
                      <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-3">
                        <FontAwesomeIcon icon={faCog} className="text-blue-400" />
                        API Állapot
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className={`p-4 rounded-lg border-2 ${
                          apiUsageStats.spotify.enabled 
                            ? apiUsageStats.spotify.rateLimited 
                              ? 'border-red-500 bg-red-900/30' 
                              : 'border-green-500 bg-green-900/30'
                            : 'border-gray-500 bg-gray-900/30'
                        }`}>
                          <div className="flex items-center gap-3 mb-3">
                            <FontAwesomeIcon icon={faSpotify} className="text-2xl text-green-500" />
                            <h4 className="font-semibold text-white">Spotify API</h4>
                          </div>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-300">Állapot:</span>
                              <span className={`font-medium ${
                                apiUsageStats.spotify.enabled 
                                  ? apiUsageStats.spotify.rateLimited 
                                    ? 'text-red-300' 
                                    : 'text-green-300'
                                  : 'text-gray-300'
                              }`}>
                                {!apiUsageStats.spotify.enabled 
                                  ? 'Letiltva'
                                  : apiUsageStats.spotify.rateLimited 
                                    ? 'Rate Limited' 
                                    : 'Aktív'}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-300">Kérések:</span>
                              <span className="text-white font-mono">
                                {apiUsageStats.spotify.currentRequests}/{apiUsageStats.spotify.maxRequests}
                              </span>
                            </div>
                            {apiUsageStats.spotify.rateLimitedUntil && (
                              <div className="flex justify-between">
                                <span className="text-gray-300">Limit lejár:</span>
                                <span className="text-red-300 text-xs">
                                  {new Date(apiUsageStats.spotify.rateLimitedUntil).toLocaleTimeString()}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="p-4 rounded-lg border-2 border-orange-500 bg-orange-900/30">
                          <div className="flex items-center gap-3 mb-3">
                            <FontAwesomeIcon icon={faMusic} className="text-2xl text-orange-500" />
                            <h4 className="font-semibold text-white">Deezer API</h4>
                          </div>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-300">Állapot:</span>
                              <span className="text-green-300 font-medium">Mindig elérhető</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-300">Limit:</span>
                              <span className="text-white font-mono">
                                {apiUsageStats.deezer.maxRequests}/6s
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="mt-4 p-3 bg-blue-900/30 border border-blue-500/50 rounded-lg">
                        <p className="text-sm text-blue-300">
                          <strong>Jelenlegi stratégia:</strong> {
                            apiUsageStats.settings.preferredApi === 'auto' ? 'Automatikus (Spotify → Deezer fallback)' :
                            apiUsageStats.settings.preferredApi === 'spotify' ? 'Csak Spotify' :
                            'Csak Deezer'
                          }
                        </p>
                      </div>
                    </div>

                    {/* Overall Statistics */}
                    <div className="bg-gray-700/40 rounded-xl p-6">
                      <h3 className="text-xl font-semibold text-white mb-4">Összesített Statisztikák</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="bg-gray-800/50 p-4 rounded-lg text-center">
                          <div className="text-2xl font-bold text-blue-400">{analyticsData.overallStats.total_unique_tracks}</div>
                          <div className="text-sm text-gray-300">Egyedi zeneszám</div>
                        </div>
                        <div className="bg-gray-800/50 p-4 rounded-lg text-center">
                          <div className="text-2xl font-bold text-green-400">{analyticsData.overallStats.total_submissions}</div>
                          <div className="text-sm text-gray-300">Összes beküldés</div>
                        </div>
                        <div className="bg-gray-800/50 p-4 rounded-lg text-center">
                          <div className="text-2xl font-bold text-green-400">{analyticsData.overallStats.spotify_tracks}</div>
                          <div className="text-sm text-gray-300">Spotify zenék</div>
                        </div>
                        <div className="bg-gray-800/50 p-4 rounded-lg text-center">
                          <div className="text-2xl font-bold text-orange-400">{analyticsData.overallStats.deezer_tracks}</div>
                          <div className="text-sm text-gray-300">Deezer zenék</div>
                        </div>
                      </div>
                    </div>

                    {/* Platform Comparison */}
                    {analyticsData.platformStats.length > 0 && (
                      <div className="bg-gray-700/40 rounded-xl p-6">
                        <h3 className="text-xl font-semibold text-white mb-4">Platform Összehasonlítás</h3>
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="border-b border-gray-600">
                                <th className="text-left py-3 text-gray-300">Platform</th>
                                <th className="text-center py-3 text-gray-300">Zeneszámok</th>
                                <th className="text-center py-3 text-gray-300">Beküldések</th>
                                <th className="text-center py-3 text-gray-300">Átlag/zene</th>
                                <th className="text-center py-3 text-gray-300">Explicit</th>
                              </tr>
                            </thead>
                            <tbody>
                              {analyticsData.platformStats.map((platform: any, index: number) => (
                                <tr key={platform.platform} className="border-b border-gray-700/50">
                                  <td className="py-3">
                                    <div className="flex items-center gap-2">
                                      {platform.platform === 'spotify' ? (
                                        <FontAwesomeIcon icon={faSpotify} className="text-green-500" />
                                      ) : (
                                        <FontAwesomeIcon icon={faMusic} className="text-orange-500" />
                                      )}
                                      <span className="text-white font-medium capitalize">{platform.platform}</span>
                                    </div>
                                  </td>
                                  <td className="text-center py-3 text-white font-mono">{platform.total_tracks}</td>
                                  <td className="text-center py-3 text-white font-mono">{platform.total_submissions}</td>
                                  <td className="text-center py-3 text-white font-mono">{Number(platform.avg_submissions_per_track).toFixed(1)}</td>
                                  <td className="text-center py-3">
                                    <span className="text-white font-mono">{platform.explicit_tracks}</span>
                                    <span className="text-gray-400 text-xs ml-1">({platform.explicit_percentage}%)</span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Top Tracks by Platform */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {analyticsData.topTracks.spotify.length > 0 && (
                        <div className="bg-gray-700/40 rounded-xl p-6">
                          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                            <FontAwesomeIcon icon={faSpotify} className="text-green-500" />
                            Top Spotify Zenék
                          </h3>
                          <div className="space-y-2">
                            {analyticsData.topTracks.spotify.slice(0, 5).map((track: any, index: number) => (
                              <div key={index} className="flex items-center justify-between p-2 bg-gray-800/50 rounded">
                                <div className="min-w-0 flex-1">
                                  <div className="text-sm font-medium text-white truncate">{track.title}</div>
                                  <div className="text-xs text-gray-400 truncate">{track.artist}</div>
                                </div>
                                <div className="text-sm text-green-400 font-mono ml-2">{track.count}x</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {analyticsData.topTracks.deezer.length > 0 && (
                        <div className="bg-gray-700/40 rounded-xl p-6">
                          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                            <FontAwesomeIcon icon={faMusic} className="text-orange-500" />
                            Top Deezer Zenék
                          </h3>
                          <div className="space-y-2">
                            {analyticsData.topTracks.deezer.slice(0, 5).map((track: any, index: number) => (
                              <div key={index} className="flex items-center justify-between p-2 bg-gray-800/50 rounded">
                                <div className="min-w-0 flex-1">
                                  <div className="text-sm font-medium text-white truncate">{track.title}</div>
                                  <div className="text-xs text-gray-400 truncate">{track.artist}</div>
                                </div>
                                <div className="text-sm text-orange-400 font-mono ml-2">{track.count}x</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Refresh Button */}
                    <div className="flex justify-center">
                      <button
                        onClick={fetchAnalytics}
                        disabled={analyticsLoading}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {analyticsLoading ? 'Frissítés...' : 'Adatok Frissítése'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-white">
                    <p>Nincs elérhető adat</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Notification System */}
        <div className="fixed top-4 right-4 z-50 space-y-2">
          {notifications.map((notification) => (
            <div
              key={notification.id}
              className={`p-4 rounded-lg shadow-lg backdrop-blur-lg border transition-all duration-300 transform animate-slide-in-right max-w-md ${
                notification.type === 'success' 
                  ? 'bg-green-900/90 border-green-500/50 text-green-100' 
                  : notification.type === 'error'
                  ? 'bg-red-900/90 border-red-500/50 text-red-100'
                  : 'bg-blue-900/90 border-blue-500/50 text-blue-100'
              }`}
            >
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-3">
                  <div className={`w-2 h-2 rounded-full ${
                    notification.type === 'success' ? 'bg-green-400' :
                    notification.type === 'error' ? 'bg-red-400' : 'bg-blue-400'
                  }`}></div>
                  <span className="font-medium">{notification.message}</span>
                </div>
                <button
                  onClick={() => removeNotification(notification.id)}
                  className="ml-4 opacity-70 hover:opacity-100 transition-opacity"
                >
                  <FontAwesomeIcon icon={faTimes} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AdminPage;