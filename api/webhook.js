export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method === 'POST') {
    const event = req.body?.meta?.event_name;
    if (event === 'order_created' || event === 'order_refunded') {
      console.log('Webhook received:', event, req.body);
    }
    return res.status(200).json({ received: true });
  }

  res.status(405).json({ error: 'Method not allowed' });
}
