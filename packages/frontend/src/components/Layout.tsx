/**
 * Main layout component
 */
import { Link } from 'react-router-dom';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header
        style={{
          padding: '1rem 2rem',
          borderBottom: '1px solid #444',
          backgroundColor: '#1a1a1a',
        }}
      >
        <nav style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
          <h1 style={{ fontSize: '1.5rem', margin: 0 }}>🔍 Snapshot Sleuth</h1>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <Link to="/" style={{ color: 'inherit', textDecoration: 'none' }}>
              Dashboard
            </Link>
            <Link to="/cases" style={{ color: 'inherit', textDecoration: 'none' }}>
              Cases
            </Link>
          </div>
        </nav>
      </header>
      <main style={{ flex: 1, padding: '2rem' }}>{children}</main>
      <footer
        style={{
          padding: '1rem 2rem',
          borderTop: '1px solid #444',
          textAlign: 'center',
          fontSize: '0.875rem',
          color: '#888',
        }}
      >
        Snapshot Sleuth - Automated Cloud Forensics and Incident Response
      </footer>
    </div>
  );
}
