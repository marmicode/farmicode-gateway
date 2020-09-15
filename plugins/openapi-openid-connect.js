const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { promisify, callbackify } = require('util');
const uuid = require('uuid');
const { ExtractJwt, Strategy: JwtStrategy } = require('passport-jwt');
const {
  applyMetadata,
  getOpenapiSpecification,
  getOpenidInfo,
} = require('./lib/openapi-utils');

const pluginName = 'openapi-openid-connect';

module.exports = {
  version: '0.1.0',
  schema: {
    $id: `${pluginName}-plugin-schema`,
  },
  init: (pluginContext) =>
    pluginContext.registerPolicy({
      name: pluginName,
      schema: {
        $id: `${pluginName}-policy-schema`,
        type: 'object',
        properties: {
          algorithms: {
            type: 'array',
            items: {
              type: 'string',
            },
          },
          audience: {
            type: 'string',
          },
          openapiSpecPath: {
            type: 'string',
          },
        },
        required: ['audience', 'openapiSpecPath'],
      },
      policy: ({ algorithms = ['RS256'], audience, openapiSpecPath }) => {
        const specPromise = getOpenapiSpecification(openapiSpecPath);

        const schemesMapPromise = specPromise.then(async (spec) => {
          return new Map(
            await Promise.all(
              Object.entries(spec.apiDoc.components?.securitySchemes ?? [])
                /* Filter "openIdConnect" security schemes only. */
                .filter(([_, scheme]) => scheme.type === 'openIdConnect')
                /* Get JWKs. */
                .map(([schemeId, scheme]) =>
                  getOpenidInfo(scheme.openIdConnectUrl).then((openidInfo) => [
                    schemeId,
                    { ...scheme, ...openidInfo },
                  ])
                )
            )
          );
        });

        return async (req, res, next) => {
          const spec = await specPromise;

          /* Add openapi metadata to request. */
          await applyMetadata({ spec, req, res });

          const securitySchemeList = req.openapi.schema.security;

          /* Skip policy if no security schemes are defined for this route. */
          if (securitySchemeList == null || securitySchemeList.length === 0) {
            next();
            return;
          }

          const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

          if (token == null) {
            res.sendStatus(401);
            return;
          }

          /* Get kid from token. */
          const { kid } = jwt.decode(token, { complete: true })?.header;

          const schemesMap = await schemesMapPromise;

          for (let securityScheme of securitySchemeList) {
            const securitySchemeName = Object.keys(securityScheme)[0];
            const requiredScopes = securityScheme[securitySchemeName];

            const { issuer, jwks } = schemesMap.get(securitySchemeName);

            const jwk = jwks.find((jwk) => jwk.kid === kid);

            /* Key not found. */
            if (jwk == null) {
              res.sendStatus(401);
              return;
            }

            const strategy = new JwtStrategy(
              {
                algorithms,
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: jwkToPem(jwk),
                issuer,
                audience,
              },
              /* Using an object with claims property
               * containing JWT claims as the user object. */
              callbackify(async (claims) => {
                const tokenScopes = claims.scopes?.split(' ');
                if (
                  !requiredScopes.every((scope) => tokenScopes?.includes(scope))
                ) {
                  throw new Error(
                    `some required scopes are missing: ${requiredScopes}`
                  );
                }

                /* Return `{claims}` as the user object to passport. */
                return { claims };
              })
            );

            /* Making sure passport strategy doesn't collide with another instance with a different configuration. */
            const strategyId = `openid-connect-${uuid.v4()}`;

            passport.use(strategyId, strategy);

            try {
              await promisify(
                passport.authenticate(strategyId, {
                  session: false,
                })
              )(req, res);
              next();
            } catch {
              res.status(403);
              res.send({
                errors: [
                  {
                    errorCode: 'missing-scopes',
                    requiredScopes,
                  },
                ],
              });
              continue;
            }
          }
        };
      },
    }),
};
