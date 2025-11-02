function ipPrefix(ipRaw: string | null | undefined): string {
  const ip = (ipRaw || '').trim();
  if (!ip) return 'unknown';
  if (ip === '::1' || ip === '127.0.0.1') return 'local';
  if (ip.includes('.')) {
    const parts = ip.split('.');
    return parts.slice(0, 3).join('.') || 'v4';
  }
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return parts.slice(0, 4).join(':') || 'v6';
  }
  return 'unknown';
}