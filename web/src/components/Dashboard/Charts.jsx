import { useRef, useEffect } from 'react';
import {
  Chart, ArcElement, Tooltip, Legend, DoughnutController,
  BarElement, CategoryScale, LinearScale, BarController,
} from 'chart.js';

Chart.register(
  ArcElement, Tooltip, Legend, DoughnutController,
  BarElement, CategoryScale, LinearScale, BarController,
);

const TOOLTIP_OPTS = {
  backgroundColor: 'rgba(12,12,15,0.95)',
  titleColor: '#fafafa',
  bodyColor: '#a1a1aa',
  borderColor: 'rgba(255,255,255,0.06)',
  borderWidth: 1,
  cornerRadius: 6,
  padding: 10,
};

export function ClassificationChart({ results }) {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => {
    if (!results?.length) return;

    const counts = {};
    results.forEach(r => { counts[r.classification] = (counts[r.classification] || 0) + 1; });

    const colorMap = {
      legitimate:    '#22c55e',
      malicious:     '#ef4444',
      suspicious:    '#eab308',
      moderate_risk: '#f97316',
      low_risk:      '#3b82f6',
    };

    const labels = Object.keys(counts);
    const data   = Object.values(counts);
    const colors = labels.map(l => colorMap[l] || '#71717a');

    chart.current?.destroy();
    chart.current = new Chart(ref.current, {
      type: 'doughnut',
      data: {
        labels: labels.map(l => l.replace('_', ' ')),
        datasets: [{ data, backgroundColor: colors, borderColor: 'rgba(9,9,11,0.8)', borderWidth: 2, hoverOffset: 4 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#71717a', font: { family: 'Inter', size: 10 }, padding: 12, usePointStyle: true },
          },
          tooltip: TOOLTIP_OPTS,
        },
      },
    });

    return () => chart.current?.destroy();
  }, [results]);

  return (
    <div className="chart-panel">
      <div className="chart-panel-title">Classification Distribution</div>
      <div style={{ height: 240 }}><canvas ref={ref} /></div>
    </div>
  );
}

export function RiskDistributionChart({ results }) {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => {
    if (!results?.length) return;

    const buckets = new Array(10).fill(0);
    results.forEach(r => { buckets[Math.min(Math.floor(r.riskScore / 10), 9)]++; });

    const labels = ['0–9','10–19','20–29','30–39','40–49','50–59','60–69','70–79','80–89','90+'];
    const colors = ['#22c55e','#22c55e','#3b82f6','#3b82f6','#eab308','#eab308','#f97316','#f97316','#ef4444','#ef4444'];

    chart.current?.destroy();
    chart.current = new Chart(ref.current, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: buckets,
          backgroundColor: colors.map(c => c + '30'),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#52525b', font: { size: 9 } } },
          y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#52525b', font: { size: 9 } } },
        },
        plugins: { legend: { display: false }, tooltip: TOOLTIP_OPTS },
      },
    });

    return () => chart.current?.destroy();
  }, [results]);

  return (
    <div className="chart-panel">
      <div className="chart-panel-title">Risk Score Distribution</div>
      <div style={{ height: 240 }}><canvas ref={ref} /></div>
    </div>
  );
}
