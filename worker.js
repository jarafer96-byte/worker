import { AwsClient } from 'https://esm.sh/aws4fetch@1.0.20';

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

    // Configurar cliente S3 con las credenciales de R2
    const r2 = new AwsClient({
      accessKeyId: env.R2_ACCESS_KEY_ID,
      secretAccessKey: env.R2_SECRET_ACCESS_KEY,
      region: 'auto',
      service: 's3',
    });

    // URL base de tu bucket (usá el endpoint de S3 de tu cuenta)
    const endpoint = 'https://a2f89bcf2254aa9ff406c31073099c0c.r2.cloudflarestorage.com';
    const url = new URL(`/${objectKey}`, endpoint);

    // Firmar la petición como URL prefirmada (PUT)
    const presigned = await r2.sign(url, {
      method: 'PUT',
      headers: { 'Content-Type': contentType },
      aws: { signQuery: true, expiresIn: 3600 },
    });

    return new Response(
      JSON.stringify({
        ok: true,
        url: presigned.url,
        key: objectKey,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};
