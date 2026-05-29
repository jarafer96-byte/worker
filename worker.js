export default {
  async fetch(request, env) {
    // Devolvemos información sobre el bucket y la compatibilidad
    const bucket = env.UPLOADS_BUCKET;
    const info = {
      bucketExists: !!bucket,
      bucketType: typeof bucket,
      // Obtenemos los métodos del prototipo del objeto bucket
      bucketMethods: bucket ? Object.getOwnPropertyNames(Object.getPrototypeOf(bucket)) : [],
      createPresignedUrlExists: bucket && typeof bucket.createPresignedUrl === 'function',
      compatibilityDate: '2024-12-16 (esperada)',
    };

    return new Response(JSON.stringify(info, null, 2), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
