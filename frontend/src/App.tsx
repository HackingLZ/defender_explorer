import { Routes, Route, Navigate } from 'react-router-dom'
import ErrorBoundary from './components/ErrorBoundary'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import ThreatDetail from './pages/ThreatDetail'
import Signatures from './pages/Signatures'
import SignatureDetail from './pages/SignatureDetail'
import ASRBrowser from './pages/ASRBrowser'
import ASRDetail from './pages/ASRDetail'
import YaraBuilder from './pages/YaraBuilder'

function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route
          path="/"
          element={
            <Layout>
              <Dashboard />
            </Layout>
          }
        />
        <Route
          path="/threats"
          element={
            <Layout>
              <Threats />
            </Layout>
          }
        />
        <Route
          path="/threats/:sigId"
          element={
            <Layout>
              <ThreatDetail />
            </Layout>
          }
        />
        <Route
          path="/signatures"
          element={
            <Layout>
              <Signatures />
            </Layout>
          }
        />
        <Route
          path="/signatures/:signatureId"
          element={
            <Layout>
              <SignatureDetail />
            </Layout>
          }
        />
        <Route
          path="/asr"
          element={
            <Layout>
              <ASRBrowser />
            </Layout>
          }
        />
        <Route
          path="/asr/:guid"
          element={
            <Layout>
              <ASRDetail />
            </Layout>
          }
        />
        <Route
          path="/yara-builder"
          element={
            <Layout>
              <YaraBuilder />
            </Layout>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ErrorBoundary>
  )
}

export default App
