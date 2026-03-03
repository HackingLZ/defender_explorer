import { useState, createContext, useContext, ReactNode, useCallback } from 'react'
import { X, CheckCircle, AlertCircle, Info, Bell, RefreshCw } from 'lucide-react'

type NotificationType = 'success' | 'error' | 'info' | 'warning' | 'sync'

interface Notification {
  id: string
  type: NotificationType
  title: string
  message?: string
  duration?: number // ms, 0 = persistent
  action?: {
    label: string
    onClick: () => void
  }
}

interface NotificationContextType {
  notifications: Notification[]
  addNotification: (notification: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  clearAll: () => void
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined)

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([])

  const addNotification = useCallback((notification: Omit<Notification, 'id'>) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`
    const newNotification: Notification = {
      ...notification,
      id,
      duration: notification.duration ?? 5000,
    }

    setNotifications(prev => [...prev, newNotification])

    // Auto-remove after duration (if not persistent)
    if (newNotification.duration && newNotification.duration > 0) {
      setTimeout(() => {
        setNotifications(prev => prev.filter(n => n.id !== id))
      }, newNotification.duration)
    }
  }, [])

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }, [])

  const clearAll = useCallback(() => {
    setNotifications([])
  }, [])

  return (
    <NotificationContext.Provider value={{ notifications, addNotification, removeNotification, clearAll }}>
      {children}
      <NotificationContainer />
    </NotificationContext.Provider>
  )
}

export function useNotifications() {
  const context = useContext(NotificationContext)
  if (!context) {
    throw new Error('useNotifications must be used within NotificationProvider')
  }
  return context
}

function NotificationContainer() {
  const { notifications, removeNotification } = useNotifications()

  if (notifications.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
      {notifications.map(notification => (
        <NotificationToast
          key={notification.id}
          notification={notification}
          onClose={() => removeNotification(notification.id)}
        />
      ))}
    </div>
  )
}

interface NotificationToastProps {
  notification: Notification
  onClose: () => void
}

function NotificationToast({ notification, onClose }: NotificationToastProps) {
  const [isExiting, setIsExiting] = useState(false)

  const handleClose = () => {
    setIsExiting(true)
    setTimeout(onClose, 200)
  }

  const icons = {
    success: CheckCircle,
    error: AlertCircle,
    info: Info,
    warning: Bell,
    sync: RefreshCw,
  }

  const colors = {
    success: {
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
      icon: 'text-green-500',
      text: 'text-green-400',
    },
    error: {
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      icon: 'text-red-500',
      text: 'text-red-400',
    },
    info: {
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      icon: 'text-blue-500',
      text: 'text-blue-400',
    },
    warning: {
      bg: 'bg-amber/10',
      border: 'border-amber/30',
      icon: 'text-amber',
      text: 'text-amber',
    },
    sync: {
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/30',
      icon: 'text-purple-500',
      text: 'text-purple-400',
    },
  }

  const Icon = icons[notification.type]
  const color = colors[notification.type]

  return (
    <div
      className={`
        ${color.bg} ${color.border} border rounded-lg p-4 shadow-xl backdrop-blur-sm
        transform transition-all duration-200
        ${isExiting ? 'opacity-0 translate-x-4' : 'opacity-100 translate-x-0'}
      `}
    >
      <div className="flex items-start gap-3">
        <Icon className={`h-5 w-5 ${color.icon} flex-shrink-0 ${
          notification.type === 'sync' ? 'animate-spin' : ''
        }`} />
        <div className="flex-1 min-w-0">
          <h4 className={`text-sm font-medium ${color.text}`}>
            {notification.title}
          </h4>
          {notification.message && (
            <p className="mt-1 text-xs text-text-dim">{notification.message}</p>
          )}
          {notification.action && (
            <button
              onClick={notification.action.onClick}
              className={`mt-2 text-xs ${color.text} hover:underline`}
            >
              {notification.action.label}
            </button>
          )}
        </div>
        <button
          onClick={handleClose}
          className="text-text-muted hover:text-text-bright"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// Hook for sync-specific notifications
export function useSyncNotifications() {
  const { addNotification, removeNotification, notifications } = useNotifications()

  const notifySyncStarted = useCallback(() => {
    // Remove any existing sync notifications first
    notifications.filter(n => n.type === 'sync').forEach(n => removeNotification(n.id))

    addNotification({
      type: 'sync',
      title: 'Downloading Signatures',
      message: 'Downloading latest Microsoft Defender definitions (~150MB). This may take a few minutes...',
      duration: 0, // Persistent until complete
    })
  }, [addNotification, removeNotification, notifications])

  const notifySyncComplete = useCallback((stats: { added: number; updated: number; removed: number }) => {
    addNotification({
      type: 'success',
      title: 'Sync Complete',
      message: `Added: ${stats.added}, Updated: ${stats.updated}, Removed: ${stats.removed}`,
      duration: 5000,
    })
  }, [addNotification])

  const notifySyncError = useCallback((error: string) => {
    addNotification({
      type: 'error',
      title: 'Sync Failed',
      message: error,
      duration: 10000,
    })
  }, [addNotification])

  return { notifySyncStarted, notifySyncComplete, notifySyncError }
}

export default NotificationToast
