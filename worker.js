async function generatePresignedUrl(endpoint, objectKey, accessKeyId, secretAccessKey, region, service, expires, contentType) {
  const verb = 'PUT';
  const host = new URL(endpoint).host;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.substring(0, 8); // YYYYMMDD

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  // Valor del credential sin codificar (para canonical request)
  const credentialValue = `${accessKeyId}/${credentialScope}`;

  // Parámetros en orden alfabético, con valores codificados para la URL
  const params = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credentialValue,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': expires.toString(),
    'X-Amz-SignedHeaders': 'host',
  };

  // Construir canonical querystring con valores SIN codificar (excepto el path que ya está codificado)
  const canonicalQuerystring = Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`) // v sin codificar
    .join('&');

  // Construir la query string para la URL final (valores codificados)
  const queryString = Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');

  const canonicalUri = '/' + objectKey; // el objectKey ya viene codificado (test%40test.com)
  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    verb,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256(canonicalRequest),
  ].join('\n');

  const signingKey = await getSignatureKey(secretAccessKey, dateStamp, region, service);
  const signature = await hmacHex(signingKey, stringToSign);

  const url = new URL(endpoint);
  url.pathname = '/' + objectKey;
  url.search = queryString + '&X-Amz-Signature=' + signature;

  return url.toString();
}
