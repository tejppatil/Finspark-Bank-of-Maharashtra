import { useState } from 'react'
import { getUser, clearAuth } from './api.js'
import Login from './pages/Login.jsx'
import Portal from './pages/Portal.jsx'
import SocConsole from './pages/SocConsole.jsx'

export default function App() {
  const [user, setUser] = useState(getUser())

  const logout = () => { clearAuth(); setUser(null) }

  if (!user) return <Login onLogin={setUser} />
  if (user.account_type === 'ANALYST') return <SocConsole user={user} onLogout={logout} />
  return <Portal user={user} onLogout={logout} />
}
