import { createContext, useContext, useState, useEffect, ReactNode } from 'react'

type Theme = 'dark' | 'light' | 'system'

interface Settings {
  autoSyncEnabled: boolean
  autoSyncTime: string // HH:MM format
  theme: Theme
}

interface SettingsContextType {
  settings: Settings
  updateSettings: (newSettings: Partial<Settings>) => void
  effectiveTheme: 'dark' | 'light'  // The actual applied theme
}

const defaultSettings: Settings = {
  autoSyncEnabled: false,
  autoSyncTime: '03:00',
  theme: 'dark',  // Default to dark theme
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined)

const STORAGE_KEY = 'defender-explorer-settings'

// Apply dark class to document
const applyDarkTheme = () => {
  document.documentElement.classList.add('dark')
  document.documentElement.classList.remove('light')
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(defaultSettings)
  const [isLoaded, setIsLoaded] = useState(false)

  // Load from localStorage after mount to avoid SSR issues
  useEffect(() => {
    let loadedSettings = defaultSettings
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        const parsed = JSON.parse(stored)
        // Validate that parsed data is an object before merging
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          loadedSettings = { ...defaultSettings, ...parsed }
          setSettings(loadedSettings)
        } else {
          console.warn('Settings: Invalid stored data format, using defaults')
          localStorage.removeItem(STORAGE_KEY)
        }
      }
    } catch (error) {
      console.warn('Settings: Failed to parse stored settings, using defaults', error)
      // Clear corrupted data
      localStorage.removeItem(STORAGE_KEY)
    }

    // Apply dark theme
    applyDarkTheme()

    setIsLoaded(true)
  }, [])

  // Save to localStorage when settings change (but only after initial load)
  useEffect(() => {
    if (isLoaded) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
    }
  }, [settings, isLoaded])

  // Always dark theme
  const effectiveTheme: 'dark' | 'light' = 'dark'

  const updateSettings = (newSettings: Partial<Settings>) => {
    setSettings((prev) => ({ ...prev, ...newSettings }))
  }

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, effectiveTheme }}>
      {children}
    </SettingsContext.Provider>
  )
}

export function useSettings() {
  const context = useContext(SettingsContext)
  if (!context) {
    // Return default values instead of throwing to prevent crashes
    return {
      settings: {
        autoSyncEnabled: false,
        autoSyncTime: '03:00',
        theme: 'dark' as Theme,
      },
      updateSettings: () => {},
      effectiveTheme: 'dark' as const,
    }
  }
  return context
}
