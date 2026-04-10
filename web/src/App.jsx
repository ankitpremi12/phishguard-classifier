import { useState } from 'react';
import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import SingleDomainCheck from './components/DomainAnalyzer/SingleDomainCheck';
import BulkAnalyzer from './components/DomainAnalyzer/BulkAnalyzer';

export default function App() {
  const [tab, setTab] = useState('single');

  return (
    <>
      <Header activeTab={tab} onTabChange={setTab} />
      <main style={{ flex: 1 }}>
        {tab === 'single' && <SingleDomainCheck />}
        {tab === 'bulk'   && <BulkAnalyzer />}
      </main>
      <Footer />
    </>
  );
}
