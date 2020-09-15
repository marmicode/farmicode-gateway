const fs = require('fs');
const { PassThrough } = require('stream');
const yaml = require('yamljs');
const {
  OpenApiContext,
} = require('express-openapi-validator/dist/framework/openapi.context');
const {
  OpenApiSpecLoader,
} = require('express-openapi-validator/dist/framework/openapi.spec.loader');
const {
  RequestValidator,
  applyOpenApiMetadata,
  security,
} = require('express-openapi-validator/dist/middlewares');
const { json } = require('express');
const { promisify } = require('util');

module.exports = {
  version: '0.1.0',
  schema: {
    $id: 'openapi-validator',
  },
  init: (pluginContext) =>
    pluginContext.registerPolicy({
      name: 'openapi-validator',
      schema: {
        $id: 'openapi-validator',
        type: 'object',
        properties: {
          openapiSpecPath: {
            type: 'string',
          },
        },
        required: ['openapiSpecPath'],
      },
      policy: ({ openapiSpecPath }) => {
        const validatorPromise = getOpenapiValidator(openapiSpecPath);

        return async (req, res, next) => {
          const validate = await validatorPromise;

          await parseReqJson(req, res);

          await validate(req, res);

          next();
        };
      },
    }),
};

async function parseReqJson(req, res) {
  /* Backup request stream. */
  req.egContext.requestStream = new PassThrough();
  req.pipe(req.egContext.requestStream);

  try {
    await promisify(json())(req, res);
  } catch {
    res.sendStatus(400);
    return;
  }
}

async function getOpenapiValidator(openapiSpecPath) {
  const spec = await new OpenApiSpecLoader({
    apiDoc: openapiSpecPath,
    $refParser: {
      mode: 'dereference',
    },
  }).load();

  const validator = new RequestValidator(spec);

  return async (req, res) => {
    const openApiContext = new OpenApiContext(spec);

    /* Add openapi metadata to request. */
    await promisify(applyOpenApiMetadata(openApiContext))(req, res);

    /* Validate security. */
    try {
      await promisify(
        security(openApiContext, {
          openIdConnect(req, scopes, schema) {
            const requestScopes = req?.user?.claims?.scopes ?? [];
            /* Fail if consumer doesn't have all scopes defined in openapi specification. */
            if (scopes.every((scope) => requestScopes.includes(scope))) {
              return true;
            }
            throw {
              status: 403,
              message: `route requires scopes: ${scopes}`,
              errorCode: 'forbidden',
            };
          },
        })
      )(req, res);
    } catch (err) {
      res.status(403);
      res.send({ errors: err.errors });
      return;
    }

    /* Validate request. */
    try {
      await promisify(validator.validate.bind(validator))(req, res);
    } catch (err) {
      res.status(err.status);
      res.send({
        errors: err.errors,
      });
    }
  };
}
