/**
 * Dashboard page
 */
export default function DashboardPage() {
  return (
    <div>
      <h1>Forensic Dashboard</h1>
      <div style={{ marginTop: '2rem' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '1rem',
          }}
        >
          <div
            style={{
              padding: '1.5rem',
              border: '1px solid #444',
              borderRadius: '8px',
              backgroundColor: '#1a1a1a',
            }}
          >
            <h3>Active Cases</h3>
            <p style={{ fontSize: '2rem', margin: '0.5rem 0' }}>0</p>
          </div>
          <div
            style={{
              padding: '1.5rem',
              border: '1px solid #444',
              borderRadius: '8px',
              backgroundColor: '#1a1a1a',
            }}
          >
            <h3>Critical Findings</h3>
            <p style={{ fontSize: '2rem', margin: '0.5rem 0' }}>0</p>
          </div>
          <div
            style={{
              padding: '1.5rem',
              border: '1px solid #444',
              borderRadius: '8px',
              backgroundColor: '#1a1a1a',
            }}
          >
            <h3>Running Workflows</h3>
            <p style={{ fontSize: '2rem', margin: '0.5rem 0' }}>0</p>
          </div>
        </div>
      </div>
    </div>
  );
}
