export default {
  async fetch(request, env) {
    // Solo acepta peticiones POST
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    // Verifica el token de autenticación
    const authToken = request.headers.get('X-Auth-Token');
    if (!authToken || authToken !== env.AUTH_TOKEN_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Parsea el body JSON
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

    // Solo permite tipos de imagen
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(contentType)) {
      return new Response('Tipo de archivo no permitido', { status: 400 });
    }

    // Construye la clave del objeto en R2
    const objectKey = `productos/${email_vendedor}/${Date.now()}-${fileName}`;
    const bucket = env.UPLOADS_BUCKET;

    // Genera la URL prefirmada para subir el archivo
    const presignedUrl = await bucket.createPresignedUrl({
      method: 'PUT',
      object: objectKey,   // parámetro correcto: 'object', no 'path'
      expiresIn: 3600,     // expira en 1 hora
    });

    // Responde con la URL y la clave
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
