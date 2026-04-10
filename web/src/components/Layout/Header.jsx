export default function Header({ activeTab, onTabChange }) {
  return (
    <header className="header">
      <div className="container header-inner">
        <div className="header-logo">
          <div className="logo-mark">PG</div>
          <span>PhishGuard</span>
        </div>
        <div className="header-tabs">
          <button
            className={`tab-btn ${activeTab === 'single' ? 'active' : ''}`}
            onClick={() => onTabChange('single')}
          >
            Domain Check
          </button>
          <button
            className={`tab-btn ${activeTab === 'bulk' ? 'active' : ''}`}
            onClick={() => onTabChange('bulk')}
          >
            Bulk Analysis
          </button>
        </div>
      </div>
    </header>
  );
}
