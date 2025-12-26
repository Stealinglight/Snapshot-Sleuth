/**
 * Case detail page
 */
import { useParams } from 'react-router-dom';

export default function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();

  return (
    <div>
      <h1>Case: {caseId}</h1>
      <div style={{ marginTop: '2rem' }}>
        <section style={{ marginBottom: '2rem' }}>
          <h2>Case Information</h2>
          <div style={{ marginTop: '1rem' }}>
            <p>Loading case details...</p>
          </div>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2>Workflow Status</h2>
          <div style={{ marginTop: '1rem' }}>
            <p>Workflow information will appear here</p>
          </div>
        </section>

        <section>
          <h2>Findings</h2>
          <div style={{ marginTop: '1rem' }}>
            <p>No findings yet</p>
          </div>
        </section>
      </div>
    </div>
  );
}
