export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({ status: 'healthy', service: 'Security Headers Checker', timestamp: new Date().toISOString() });
}
