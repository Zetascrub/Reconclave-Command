import { useState } from 'react'

export default function LoginScreen({ onLogin }: { onLogin: (username: string, password: string) => Promise<void> }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    setError('')
    setBusy(true)
    try {
      await onLogin(username.trim(), password)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return <div className="app-shell login-shell">
    <div className="ambient ambient-one" /><div className="ambient ambient-two" />
    <form className="login-card panel" onSubmit={(event) => { event.preventDefault(); if (!busy) submit() }}>
      <div className="brand-mark"><span>R</span></div>
      <div className="brand"><strong>RECONCLAVE</strong><span>OPERATIONS DECK</span></div>
      <p className="login-sub">Sign in with your operator account.</p>
      <label className="field"><span>USERNAME</span><input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} /></label>
      <label className="field"><span>PASSWORD</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      {error && <div className="inspection-error">{error}</div>}
      <button type="submit" className="primary-action login-submit" disabled={busy || !username.trim() || !password}>{busy ? 'SIGNING IN…' : 'SIGN IN'}</button>
    </form>
  </div>
}
