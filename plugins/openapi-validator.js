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
          openapiPath: {
            type: 'string',
          },
        },
        required: ['openapiPath'],
      },
      policy: ({ openapiPath }) => {
        const specPromise = new OpenApiSpecLoader({
          apiDoc: openapiPath,
          $refParser: {
            mode: 'dereference',
          },
        }).load();

        const validatorPromise = specPromise.then(
          (spec) => new RequestValidator(spec)
        );

        return async (req, res, next) => {
          const spec = await specPromise;

          const validator = await validatorPromise;

          /* Backup request stream. */
          req.egContext.requestStream = new PassThrough();
          req.pipe(req.egContext.requestStream);

          try {
            await promisify(json())(req, res);
          } catch {
            res.sendStatus(400);
            return;
          }

          await promisify(applyOpenApiMetadata(new OpenApiContext(spec)))(
            req,
            res
          );

          try {
            await promisify(validator.validate.bind(validator))(req, res);
          } catch (err) {
            res.status(err.status);
            res.send({
              errors: err.errors,
            });
          }

          next();
        };
      },
    }),
};
