export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.status(200).json({
    status: 'ok',
    version: '1.0.0',
    engine: 'PhishGuard Heuristic Engine',
    timestamp: new Date().toISOString(),
  });
}
