const { promisify } = require('util');
const axios = require('axios');
const {
  applyOpenApiMetadata,
} = require('express-openapi-validator/dist/middlewares');
const {
  OpenApiContext,
} = require('express-openapi-validator/dist/framework/openapi.context');
const {
  OpenApiSpecLoader,
} = require('express-openapi-validator/dist/framework/openapi.spec.loader');

module.exports = {
  /**
   * Adds `openapi` metadata to `req`.
   */
  async applyMetadata({ spec, req, res }) {
    const openApiContext = new OpenApiContext(spec);
    await promisify(applyOpenApiMetadata(openApiContext))(req, res);
  },
  async getOpenidInfo(openidConnectUrl) {
    const discoveryResponse = await axios.get(openidConnectUrl);
    const jwksUri = discoveryResponse.data.jwks_uri;
    const jwksResponse = await axios.get(jwksUri);
    return {
      issuer: discoveryResponse.data.issuer,
      jwks: jwksResponse.data.keys,
    };
  },
  async getOpenapiSpecification(openapiSpecPath) {
    return await new OpenApiSpecLoader({
      apiDoc: openapiSpecPath,
      $refParser: {
        mode: 'dereference',
      },
    }).load();
  },
};
