import React from 'react'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 bg-red-500/10 border border-red-500 m-4">
          <h2 className="text-xl font-bold text-red-500 mb-2">Something went wrong</h2>
          <p className="text-sm text-red-400">
            An unexpected error occurred. Please try again or reload the page.
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="mt-4 px-4 py-2 bg-red-500 text-white rounded"
          >
            Try again
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
