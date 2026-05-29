export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    const authToken = request.headers.get('X-Auth-Token');
    if (!authToken || authToken !== env.AUTH_TOKEN_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }

    let requestData;
    try {
      requestData = await request.json();
    } catch (e) {
      return new Response('Invalid JSON', { status: 400 });
    }

    const { fileName, contentType, email_vendedor } = requestData;
    if (!fileName || !contentType || !email_vendedor) {
      return new Response('Missing fileName, contentType, or email_vendedor', { status: 400 });
    }

    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(contentType)) {
      return new Response('Tipo de archivo no permitido', { status: 400 });
    }

    const objectKey = `productos/${email_vendedor}/${Date.now()}-${fileName}`;

    // Endpoint nativo de R2
    const endpoint = 'https://mpage-db.a2f89bcf2254aa9ff406c31073099c0c.r2.cloudflarestorage.com';

    // Generar la URL prefirmada
    const presignedUrl = await generatePresignedUrl(
      endpoint,
      objectKey,
      env.R2_ACCESS_KEY_ID,
      env.R2_SECRET_ACCESS_KEY,
      'auto',
      's3',
      3600,
      contentType
    );

    return new Response(
      JSON.stringify({
        ok: true,
        url: presignedUrl,
        key: objectKey,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};

// ====== Funciones auxiliares para la firma AWS V4 ======

async function generatePresignedUrl(endpoint, objectKey, accessKeyId, secretAccessKey, region, service, expires, contentType) {
  const verb = 'PUT';
  const host = new URL(endpoint).host;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.substring(0, 8); // YYYYMMDD

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const credentialValue = `${accessKeyId}/${credentialScope}`;

  // Parámetros para la URL final (codificados normalmente)
  const encodedParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': encodeURIComponent(credentialValue),
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': expires.toString(),
    'X-Amz-SignedHeaders': 'host',
  };

  // Parámetros para construir la canonical request (valores sin codificar)
  const canonicalParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credentialValue, // ya incluye las barras
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': expires.toString(),
    'X-Amz-SignedHeaders': 'host',
  };

  // Orden alfabético
  const sortedKeys = Object.keys(canonicalParams).sort();

  // CORRECCIÓN 1: canonicalUri debe codificar caracteres especiales pero mantener las '/' sin codificar
  const canonicalUri = '/' + encodeURIComponent(objectKey).replace(/%2F/g, '/');

  // CORRECCIÓN 2: canonicalQuerystring debe codificar los valores (las barras se vuelven %2F)
  const canonicalQuerystring = sortedKeys
    .map(key => `${key}=${encodeURIComponent(canonicalParams[key])}`)
    .join('&');

  // Query string para la URL final: valores codificados (ya lo teníamos)
  const queryString = sortedKeys
    .map(key => `${key}=${encodedParams[key]}`)
    .join('&');

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
  url.pathname = '/' + objectKey; // la URL final no necesita codificación manual, el objeto URL se encarga
  url.search = queryString + '&X-Amz-Signature=' + signature;

  return url.toString();
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(key, data) {
  const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const dataBuffer = new TextEncoder().encode(data);
  const hmacBuffer = await crypto.subtle.sign(
    'HMAC',
    await crypto.subtle.importKey('raw', keyBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    dataBuffer
  );
  const hmacArray = Array.from(new Uint8Array(hmacBuffer));
  return hmacArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSignatureKey(secretAccessKey, dateStamp, region, service) {
  const kDate = await hmacRaw('AWS4' + secretAccessKey, dateStamp);
  const kRegion = await hmacRaw(kDate, region);
  const kService = await hmacRaw(kRegion, service);
  const kSigning = await hmacRaw(kService, 'aws4_request');
  return kSigning;
}

async function hmacRaw(key, data) {
  const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const dataBuffer = new TextEncoder().encode(data);
  const hmacBuffer = await crypto.subtle.sign(
    'HMAC',
    await crypto.subtle.importKey('raw', keyBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    dataBuffer
  );
  return new Uint8Array(hmacBuffer);
}
