export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const targetUrl = url.startsWith('http') ? url : `https://${url}`;
    const response = await fetch(targetUrl, { method: 'HEAD', redirect: 'follow' });
    const headers = Object.fromEntries(response.headers.entries());

    const securityHeaders = {
      'strict-transport-security': { name: 'HSTS', required: true, description: 'Forces HTTPS connections' },
      'content-security-policy': { name: 'CSP', required: true, description: 'Prevents XSS and data injection' },
      'x-frame-options': { name: 'X-Frame-Options', required: true, description: 'Prevents clickjacking' },
      'x-content-type-options': { name: 'X-Content-Type-Options', required: true, description: 'Prevents MIME sniffing' },
      'referrer-policy': { name: 'Referrer-Policy', required: false, description: 'Controls referrer information' },
      'permissions-policy': { name: 'Permissions-Policy', required: false, description: 'Controls browser features' },
      'x-xss-protection': { name: 'X-XSS-Protection', required: false, description: 'Legacy XSS protection' },
      'cross-origin-embedder-policy': { name: 'COEP', required: false, description: 'Cross-origin embedding control' },
      'cross-origin-opener-policy': { name: 'COOP', required: false, description: 'Cross-origin window control' },
      'cross-origin-resource-policy': { name: 'CORP', required: false, description: 'Cross-origin resource access' }
    };

    const results = Object.entries(securityHeaders).map(([key, config]) => {
      const value = headers[key] || headers[key.replace(/-/g, '_')] || null;
      const present = !!value;
      let grade = present ? 'A' : (config.required ? 'F' : 'C');

      if (present && key === 'content-security-policy' && value.includes("'unsafe-inline'")) {
        grade = 'C';
      }

      return {
        header: config.name,
        key: key,
        present,
        value: present ? value.substring(0, 200) : null,
        required: config.required,
        description: config.description,
        grade
      };
    });

    const score = results.filter(r => r.present && r.grade === 'A').length;
    const totalRequired = results.filter(r => r.required).length;
    const totalPresent = results.filter(r => r.present).length;

    let overallGrade = 'F';
    const percentage = (score / totalRequired) * 100;
    if (percentage >= 90) overallGrade = 'A';
    else if (percentage >= 70) overallGrade = 'B';
    else if (percentage >= 50) overallGrade = 'C';
    else if (percentage >= 30) overallGrade = 'D';

    res.json({
      url: targetUrl,
      status: response.status,
      overallGrade,
      score: `${totalPresent}/${results.length}`,
      requiredScore: `${score}/${totalRequired}`,
      headers: results,
      recommendations: results.filter(r => !r.present && r.required).map(r => ({
        header: r.header,
        action: `Add ${r.header} header to improve security`
      })),
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to analyze headers', message: error.message });
  }
}
