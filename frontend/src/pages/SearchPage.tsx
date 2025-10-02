import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faMusic, faSearch, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';
import { faSpotify } from '@fortawesome/free-brands-svg-icons';
import { searchTracks, submitTrack, getSettings, getWhatsPlaying } from '../utils/api';
import LightRays from '../components/LightRays';

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

type SubmitStatus = 'submitting' | 'success' | 'error' | null;

const SearchPage: React.FC = () => {
  const [query, setQuery] = useState<string>('');
  const [results, setResults] = useState<Track[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [cache, setCache] = useState<Record<string, Track[]>>({});
  const [submitStatus, setSubmitStatus] = useState<Record<string, SubmitStatus>>({});
  const [error, setError] = useState<string | null>(null);
  const [isScrolled, setIsScrolled] = useState<boolean>(false);
  const [notification, setNotification] = useState<{message: string, type: 'success' | 'error'} | null>(null);
  const [hasSearched, setHasSearched] = useState<boolean>(false);
  const [lastSearchedQuery, setLastSearchedQuery] = useState<string>('');
  const [settings, setSettings] = useState<any>({
    site_mode: 'normal',
    maintenance_message: ''
  });
  const [settingsLoaded, setSettingsLoaded] = useState<boolean>(false);
  const [currentlyPlaying, setCurrentlyPlaying] = useState<any>(null);
  const [playingLoading, setPlayingLoading] = useState<boolean>(false);
  const [localProgress, setLocalProgress] = useState<number>(0);
  const [lastUpdateTime, setLastUpdateTime] = useState<number>(0);

  const loadSettings = useCallback(async () => {
    try {
      const settingsData = await getSettings();
      setSettings(settingsData);
      setSettingsLoaded(true);
    } catch (error) {
      console.error('Error loading settings:', error);
      // If settings fail to load, use defaults (everything enabled)
      setSettingsLoaded(true);
    }
  }, []);

  const loadCurrentlyPlaying = useCallback(async () => {
    if (settings.site_mode === 'whats_playing') {
      // Only show loading on first load when there's no data at all
      if (!currentlyPlaying) {
        setPlayingLoading(true);
      }
      // Don't show loading when refreshing existing data
      
      try {
        const playing = await getWhatsPlaying();
        
        // Check if it's the same track
        const sameTrack = currentlyPlaying && currentlyPlaying.id === playing.id;
        
        if (sameTrack) {
          // Same track - only update progress and playing state, keep other data
          setCurrentlyPlaying((prev: any) => ({
            ...prev,
            progress_ms: playing.progress_ms,
            isPlaying: playing.isPlaying,
            timestamp: playing.timestamp
          }));
        } else {
          // New track or no previous track - full update
          setCurrentlyPlaying(playing);
        }
        
        if (playing && playing.isPlaying && playing.progress_ms !== undefined) {
          setLocalProgress(playing.progress_ms);
          setLastUpdateTime(Date.now());
        }
      } catch (error) {
        console.error('Error loading currently playing:', error);
      } finally {
        setPlayingLoading(false);
      }
    }
  }, [settings.site_mode, currentlyPlaying]);

  const performSearch = useCallback(async (searchQuery: string = query) => {
    if (settings.site_mode === 'maintenance') {
      setError(settings.maintenance_message || 'Az oldal jelenleg karbantartás alatt áll.');
      return;
    }

    if (searchQuery.length < 3) {
      setResults([]);
      setError('A kereséshez legalább 3 karaktert adj meg!');
      setHasSearched(false);
      return;
    }

    setHasSearched(true);
    setLastSearchedQuery(searchQuery);
/*  */
    if (cache[searchQuery]) {
      setResults(cache[searchQuery]);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const tracks = await searchTracks(searchQuery);
      setResults(tracks);
      setCache(prev => ({ ...prev, [searchQuery]: tracks }));
    } catch (error: any) {
      console.error('Search error:', error);
      setError(error.message || 'Keresési hiba történt');
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [query, cache]);

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      performSearch();
    }
  };

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  useEffect(() => {
    loadCurrentlyPlaying();
  }, [settings.site_mode]); // Only trigger when site_mode changes, not on every loadCurrentlyPlaying change

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 30);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Ref to track if we need to refresh when song ends
  const needsRefresh = useRef(false);

  // Dynamic progress bar updates - pure local state, minimal API calls
  useEffect(() => {
    if (!currentlyPlaying?.isPlaying || !currentlyPlaying?.duration_ms) return;

    const interval = setInterval(() => {
      if (lastUpdateTime && currentlyPlaying?.progress_ms !== undefined) {
        const elapsed = Date.now() - lastUpdateTime;
        const newProgress = localProgress + elapsed;
        
        // Check if song ended - mark for refresh but don't call API repeatedly
        if (newProgress >= currentlyPlaying.duration_ms) {
          setLocalProgress(currentlyPlaying.duration_ms); // Set to end
          if (!needsRefresh.current) {
            needsRefresh.current = true;
            // Use setTimeout to avoid calling API from interval
            setTimeout(() => {
              loadCurrentlyPlaying();
              needsRefresh.current = false;
            }, 100);
          }
          return;
        }
        
        setLocalProgress(newProgress);
        setLastUpdateTime(Date.now());
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [currentlyPlaying, localProgress, lastUpdateTime]); // Removed loadCurrentlyPlaying from deps

  // Auto refresh every 20 seconds to stay in sync (backend has its own caching)
  useEffect(() => {
    if (settings.site_mode !== 'whats_playing') return;

    const refreshInterval = setInterval(() => {
      loadCurrentlyPlaying();
    }, 20000);

    return () => clearInterval(refreshInterval);
  }, [settings.site_mode]); // Removed loadCurrentlyPlaying to prevent excessive re-renders

  const handleSubmit = async (track: Track): Promise<void> => {
    if (settings.site_mode !== 'normal') {
      setNotification({
        message: settings.site_mode === 'maintenance' 
          ? (settings.maintenance_message || 'Az oldal jelenleg karbantartás alatt áll.')
          : 'A zeneszám beküldés jelenleg nem érhető el.',
        type: 'error'
      });
      setTimeout(() => {
        setNotification(null);
      }, 5000);
      return;
    }

    setSubmitStatus(prev => ({ ...prev, [track.id]: 'submitting' }));
    
    try {
      await submitTrack(track, 'anonymous');
      
      setSubmitStatus(prev => ({ ...prev, [track.id]: 'success' }));
      setNotification({
        message: `"${track.title}" sikeresen beküldve!`,
        type: 'success'
      });
      
      setTimeout(() => {
        setSubmitStatus(prev => ({ ...prev, [track.id]: null }));
      }, 60000); // 1 perc = 60000ms
      
      setTimeout(() => {
        setNotification(null);
      }, 5000);
      
    } catch (error) {
      console.error('Submit error:', error);
      setSubmitStatus(prev => ({ ...prev, [track.id]: 'error' }));
      // setNotification({
      //   message: 'Hiba történt a beküldés során!',
      //   type: 'error'
      // });
      console.log("Nem műkdött a feltötlés szóval ez lehet baj de nem fixne leeht hogy csak béna a user :D")
      
      setTimeout(() => {
        setSubmitStatus(prev => ({ ...prev, [track.id]: null }));
      }, 3000);
      
      setTimeout(() => {
        setNotification(null);
      }, 5000);
    }
  };

  const getSubmitButtonText = (trackId: string): string => {
    const status = submitStatus[trackId];
    switch (status) {
      case 'submitting': return 'Submitting...';
      case 'success': return 'Submitted!';
      case 'error': return 'Error - Try Again';
      default: return 'Submit';
    }
  };

  const getSubmitButtonClass = (trackId: string): string => {
    const status = submitStatus[trackId];
    const baseClass = 'px-4 py-2 rounded-lg font-medium transition-colors ';
    
    switch (status) {
      case 'submitting': 
        return baseClass + 'bg-yellow-500 text-white cursor-not-allowed';
      case 'success': 
        return baseClass + 'bg-green-500 text-white cursor-not-allowed';
      case 'error': 
        return baseClass + 'bg-red-500 text-white hover:bg-red-600';
      default: 
        return baseClass + 'bg-spotify-green text-white hover:bg-green-600';
    }
  };

  // Show loading screen while settings are being loaded
  if (!settingsLoaded) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-4 relative">
        <div className="absolute inset-0">
          <LightRays
            raysOrigin="top-center"
            raysColor="#ffffff"
            raysSpeed={0.8}
            lightSpread={1.2}
            rayLength={1.5}
            followMouse={true}
            mouseInfluence={0.05}
            noiseAmount={0.02}
            distortion={0.01}
          />
        </div>
        <div className="absolute inset-0 bg-black/30"></div>
        <div className="relative z-10 flex flex-col items-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white mb-4"></div>
          <p className="text-white text-lg">Betöltés...</p>
        </div>
      </div>
    );
  }

  // Show maintenance page
  if (settings.site_mode === 'maintenance') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-4 relative">
        <div className="absolute inset-0">
          <LightRays
            raysOrigin="top-center"
            raysColor="#ffffff"
            raysSpeed={0.8}
            lightSpread={1.2}
            rayLength={1.5}
            followMouse={true}
            mouseInfluence={0.05}
            noiseAmount={0.02}
            distortion={0.01}
          />
        </div>
        <div className="absolute inset-0 bg-black/30"></div>
        <div className="w-full max-w-2xl relative z-10 flex flex-col items-center text-center">
          <div className="animate-fade-in">
            <h1 className="text-4xl sm:text-6xl font-bold text-white drop-shadow-2xl mb-6">
              Karbantartás
            </h1>
            <div className="bg-black/60 backdrop-blur-lg rounded-2xl p-8 border border-white/20">
              <p className="text-white/90 text-lg sm:text-xl drop-shadow-lg font-medium mb-4">
                {settings.maintenance_message || 'A keresőoldal jelenleg nem érhető el.'}
              </p>
              <p className="text-white/70 text-sm">
                Kérjük, próbáld meg később!
              </p>
            </div>
          </div>
          <div className={`fixed top-4 right-4 z-20 transition-all duration-300 hidden md:block ${
            !isScrolled ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-2 pointer-events-none'
          }`}>
            <Link 
              to="/admin" 
              className="bg-white/15 backdrop-blur-sm text-white px-4 py-2 rounded-lg hover:bg-white/25 transition-all border border-white/30 shadow-lg"
            >
              Admin
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 relative">
      <div className="absolute inset-0">
        <LightRays
          raysOrigin="top-center"
          raysColor="#fafafa"
          raysSpeed={0.8}
          lightSpread={1.2}
          rayLength={1.5}
          followMouse={true}
          mouseInfluence={0.05}
          noiseAmount={0.02}
          distortion={0.01}
        />
      </div>
      <div className="absolute inset-0 bg-black/30"></div>
      <div className="w-full max-w-4xl relative z-10 flex flex-col items-center">
        <div className="text-center mb-8 sm:mb-12 mt-12 sm:mt-20 animate-fade-in">
          <h1 className="text-4xl sm:text-6xl font-bold text-white drop-shadow-2xl mb-4 sm:mb-6 px-4">
             Sulibál
          </h1>
          <p className="text-white/90 text-lg sm:text-xl drop-shadow-lg font-medium px-4">Music search and submission</p>
          <div className="mt-3 sm:mt-4 w-24 sm:w-32 h-1 bg-white/50 mx-auto rounded-full"></div>
        </div>

        {/* Search section - hidden in whats_playing mode */}
        {settings.site_mode !== 'whats_playing' && (
          <div className="mb-8 sm:mb-12 w-full max-w-2xl px-4">
            <div className="flex items-center gap-2 sm:gap-3">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Search for music..."
                className={`px-4 sm:px-6 py-3 sm:py-4 text-base sm:text-lg border border-white/20 focus:ring-2 focus:ring-white/30 focus:border-white/40 outline-none bg-black/60 backdrop-blur-lg text-white placeholder-white/70 shadow-xl transition-all duration-500 ease-in-out rounded-2xl ${
                  query.length >= 3 ? 'w-[calc(100%-100px)] sm:w-[calc(100%-140px)]' : 'w-full'
                }`}
              />
              <button
                onClick={() => performSearch()}
                disabled={query.length < 3 || loading || settings.site_mode === 'maintenance'}
                className={`search-button flex items-center gap-1 sm:gap-2 px-3 sm:px-6 py-3 sm:py-4 justify-center whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-500 ease-in-out hover:scale-105 active:scale-95 rounded-2xl bg-gradient-to-b from-gray-800 to-gray-900 border border-gray-600 text-white hover:from-gray-700 hover:to-gray-800 ${
                  query.length >= 3 ? 'w-[80px] sm:w-[120px] opacity-100 scale-100' : 'w-0 opacity-0 scale-90 pointer-events-none overflow-hidden'
                }`}
              >
                {loading ? (
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                ) : (
                  <>
                    <FontAwesomeIcon icon={faSearch} className="text-base sm:text-lg" />
                    <span className="hidden text-xs sm:text-sm font-medium">Search</span>
                  </>
                )}
              </button>
            </div>
            <div className="mt-2 text-center">
              <p className="text-sm text-white/60 drop-shadow">
                {settings.site_mode === 'maintenance' ?
                  (settings.maintenance_message || 'Az oldal jelenleg karbantartás alatt áll') :
                  query.length < 3 ? 
                  'Adj meg legalább 3 karaktert a kereséshez' :
                  loading ? 
                  'Keresés folyamatban...' :
                  'Nyomd meg az Enter-t vagy a Keresés gombot a keresés indításához'
                }
              </p>
            </div>
          </div>
        )}

        {results.length > 0 && settings.site_mode !== 'whats_playing' && (
          <div className="w-full max-w-2xl space-y-3 sm:space-y-4 px-4">
            <h2 className="text-lg sm:text-xl font-semibold text-white drop-shadow-lg mb-3 sm:mb-4">
              Találatok ({results.length})
            </h2>
            
            {results.map((track) => (
              <div
                key={track.id}
                className="bg-black/60 backdrop-blur-xl rounded-2xl shadow-2xl p-4 sm:p-6 border border-white/20 hover:border-white/40 hover:bg-black/40 transition-all duration-300 cursor-pointer"
              >
                <div className="flex items-center space-x-3 sm:space-x-4">
                  {track.thumbnail && (
                    <img
                      src={track.thumbnail}
                      alt={track.title}
                      className="w-16 h-16 sm:w-20 sm:h-20 rounded-lg object-cover flex-shrink-0"
                    />
                  )}
                  
                  <div className="flex-grow min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-base sm:text-lg font-semibold text-white truncate">
                        {track.title}
                      </h3>
                      {track.explicit && (
                        <FontAwesomeIcon 
                          icon={faExclamationTriangle} 
                          className="text-red-500 text-sm flex-shrink-0" 
                          title="Explicit tartalom"
                        />
                      )}
                      {track.platform && (
                        <div className={`px-2 py-0.5 text-xs rounded-full text-white flex items-center gap-1 flex-shrink-0 ${
                          track.platform === 'spotify' 
                            ? 'bg-green-600/80' 
                            : 'bg-orange-600/80'
                        }`}>
                          {track.platform === 'spotify' ? (
                            <>
                              <FontAwesomeIcon icon={faSpotify} className="text-xs" />
                              <span>Spotify</span>
                            </>
                          ) : (
                            <>
                              <FontAwesomeIcon icon={faMusic} className="text-xs" />
                              <span>Deezer</span>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                    <p className="text-sm sm:text-base text-white/80 mb-2 truncate">
                      {track.artist}
                    </p>
                  </div>
                  
                  <button
                    onClick={() => handleSubmit(track)}
                    disabled={submitStatus[track.id] === 'submitting' || submitStatus[track.id] === 'success' || settings.site_mode !== 'normal'}
                    className="sm:block hidden disabled:opacity-50 disabled:cursor-not-allowed px-3 sm:px-4 py-2 rounded-lg bg-gradient-to-b from-gray-800 to-gray-900 border border-gray-600 text-white hover:from-gray-700 hover:to-gray-800 transition-colors font-medium text-sm sm:text-base flex-shrink-0"
                    title={`Submit: ${track.title} - ${track.artist}`}
                  >
                    Submit
                  </button>
                  <button
                    onClick={() => handleSubmit(track)}
                    disabled={submitStatus[track.id] === 'submitting' || submitStatus[track.id] === 'success' || settings.site_mode !== 'normal'}
                    className="sm:hidden flex items-center justify-center w-10 h-10 sm:w-12 sm:h-12 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg bg-gradient-to-b from-gray-800 to-gray-900 border border-gray-600 text-white hover:from-gray-700 hover:to-gray-800 transition-colors flex-shrink-0"
                    title={`Submit: ${track.title} - ${track.artist}`}
                  >
                    <FontAwesomeIcon icon={faMusic} className="text-base" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {hasSearched && !loading && results.length === 0 && !error && settings.site_mode !== 'whats_playing' && (
          <div className="w-full max-w-2xl text-center py-8 sm:py-12 px-4">
            <p className="text-white/90 drop-shadow-lg text-base sm:text-lg">
              Nincs találat erre: "{query}"
            </p>
            <p className="text-white/70 drop-shadow mt-2 text-sm sm:text-base">
              Próbálj más kulcsszavakkal keresni
            </p>
          </div>
        )}

        {error && (
          <div className="w-full max-w-2xl mb-6 sm:mb-8 mx-4 bg-red-500/20 backdrop-blur-lg border border-red-500/30 text-white px-4 sm:px-6 py-3 sm:py-4 rounded-2xl">
            <p className="font-medium text-sm sm:text-base">⚠️ {error}</p>
            <button 
              onClick={() => setError(null)}
              className="mt-2 text-xs sm:text-sm underline hover:no-underline"
            >
              Elrejtés
            </button>
          </div>
        )}

        {/* What's Playing - Only show in whats_playing mode */}
        {settings.site_mode === 'whats_playing' && (
          <div className="w-full max-w-2xl mt-6 sm:mt-8 px-4">
            <div className="bg-black/60 backdrop-blur-xl rounded-2xl shadow-2xl p-4 sm:p-6 border border-white/20">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                  <FontAwesomeIcon icon={faMusic} className="text-white text-sm" />
                </div>
                <h2 className="text-xl font-semibold text-white drop-shadow-lg">
                  Most szól
                </h2>
              </div>
              
              {settings.maintenance_message && (
                <div className="mb-6 p-4 bg-green-500/20 backdrop-blur-lg border border-green-500/30 text-white rounded-xl">
                  <p className="font-medium">🎵 {settings.maintenance_message}</p>
                </div>
              )}
              
              {playingLoading && !currentlyPlaying ? (
                <div className="flex items-center justify-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white mb-2"></div>
                  <p className="text-white/70 ml-3">Betöltés...</p>
                </div>
              ) : currentlyPlaying && currentlyPlaying.isPlaying ? (
                <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6">
                  <div className="flex flex-col sm:flex-row items-center sm:items-start gap-4 sm:gap-6">
                    {currentlyPlaying.image && (
                      <img 
                        src={currentlyPlaying.image} 
                        alt={currentlyPlaying.name}
                        className="w-24 h-24 sm:w-20 sm:h-20 rounded-lg shadow-lg flex-shrink-0"
                      />
                    )}
                    <div className="flex-1 text-center sm:text-left w-full">
                      <div className="mb-4">
                        <h3 className="text-white font-bold text-xl sm:text-lg mb-2">{currentlyPlaying.name}</h3>
                        <p className="text-green-300 text-lg sm:text-base mb-2">{currentlyPlaying.artist}</p>
                        <p className="text-white/60 text-base sm:text-sm">{currentlyPlaying.album}</p>
                      </div>
                      
                      {/* Progress Bar */}
                      {currentlyPlaying.progress_ms !== undefined && currentlyPlaying.duration_ms && (
                        <div className="mb-4">
                          <div className="flex items-center justify-between text-sm text-white/70 mb-2">
                            <span>{Math.floor(localProgress / 1000 / 60)}:{String(Math.floor((localProgress / 1000) % 60)).padStart(2, '0')}</span>
                            <span>{Math.floor(currentlyPlaying.duration_ms / 1000 / 60)}:{String(Math.floor((currentlyPlaying.duration_ms / 1000) % 60)).padStart(2, '0')}</span>
                          </div>
                          <div className="w-full bg-gray-600/50 rounded-full h-2">
                            <div 
                              className="bg-green-500 h-2 rounded-full transition-all duration-500 ease-linear"
                              style={{ width: `${(localProgress / currentlyPlaying.duration_ms) * 100}%` }}
                            ></div>
                          </div>
                          <div className="text-center mt-2">
                            <span className="text-white/60 text-sm">
                              Még {Math.floor((currentlyPlaying.duration_ms - localProgress) / 1000 / 60)} perc {Math.floor(((currentlyPlaying.duration_ms - localProgress) / 1000) % 60)} másodperc hátra
                            </span>
                          </div>
                        </div>
                      )}
                      
                      <a 
                        href={currentlyPlaying.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="block w-full bg-green-500 hover:bg-green-600 text-white py-3 px-6 rounded-lg text-base font-medium transition-colors text-center"
                      >
                        Megnyitás Spotify-ban
                      </a>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-6 text-center">
                  <div className="text-4xl mb-3">🎵</div>
                  <h3 className="text-white font-medium mb-2">Jelenleg nem szól zene</h3>
                  <p className="text-white/70 text-sm">
                    {currentlyPlaying?.message || 'Próbáld meg később!'}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Notification */}
        {notification && (
          <div className={`fixed top-4 left-1/2 transform -translate-x-1/2 z-50 px-6 py-4 rounded-lg shadow-lg backdrop-blur-lg border transition-all duration-300 ${
            notification.type === 'success' 
              ? 'bg-green-500/90 border-green-400 text-white' 
              : 'bg-red-500/90 border-red-400 text-white'
          }`}>
            <div className="flex items-center gap-2">
              <span className="text-lg">
                {notification.type === 'success' ? '✅' : '❌'}
              </span>
              <span className="font-medium">{notification.message}</span>
            </div>
          </div>
        )}

        {/* Developed by */}
        <div className="w-full max-w-2xl mt-6 sm:mt-8 text-center px-4">
          <p className="text-white/30 text-xs">Developed by mxte • v0.5.0</p>
        </div>
        
        <div className={`fixed top-4 right-4 z-20 transition-all duration-300 hidden md:block ${
          !isScrolled ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-2 pointer-events-none'
        }`}>
          <Link 
            to="/admin" 
            className="bg-white/15 backdrop-blur-sm text-white px-4 py-2 rounded-lg hover:bg-white/25 transition-all border border-white/30 shadow-lg"
          >
            Admin
          </Link>
        </div>
        
      </div>
    </div>
  );
};

export default SearchPage;