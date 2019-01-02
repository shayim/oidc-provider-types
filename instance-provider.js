// eslint-disable-next-line no-unused-vars
const instanceOfProvider = {
  configuration: Function, // configuration
  app: {
    subdomainOffset: 2,
    proxy: false,
    env: 'development'
  },
  defaultHttpOptions: {
    headers: {
      'User-Agent': 'oidc-provider/5.5.2 (http://localhost:3000)'
    },
    timeout: 1500,
    retry: 0,
    followRedirect: false
  },
  responseModes: new Map([
    ['query', Function], // bound
    ['fragment', Function], // bound
    ['form_post', Function], // bound formPost
    ['web_message', Function], // bound webMessage
    ['jwt', Function], // bound jwtResponseModes // Async
    ['query.jwt', Function], // bound jwtResponseModes // Async
    ['fragment.jwt', Function], // bound jwtResponseModes // Async
    ['form_post.jwt', Function], // bound jwtResponseModes // Async
    ['web_message.jwt', Function] // bound jwtResponseModes // Async
  ]),
  grantTypeHandlers: new Map([
    ['authorization_code', Function], // Async authorizationCodeResponse
    ['refresh_token', Function], // Async refreshTokenResponse
    ['urn:ietf:params:oauth:grant-type:device_code', Function] // Async authorizationCodeResponse
  ]),

  grantTypeDupes: new Map(),
  grantTypeParams: new Map([
    [undefined, new Set([
      'grant_type',
      'code',
      'redirect_uri',
      'code_verifier',
      'refresh_token',
      'scope',
      'device_code',
      'client_id',
      'client_assertion',
      'client_assertion_type',
      'client_secret'
    ])],
    ['authorization_code', new Set([
      'grant_type',
      'code',
      'redirect_uri',
      'code_verifier'
    ])],
    ['refresh_token', new Set([
      'grant_type',
      'refresh_token',
      'scope'
    ])],
    ['urn:ietf:params:oauth:grant-type:device_code', new Set([
      'grant_type',
      'device_code',
      'code_verifier'
    ])]
  ]),
  Account: {
    findById: Function // findById
  },
  Claims: Function, // Claims,
  BaseToken: Function, // BaseToken]
  IdToken: Function, // IdToken]
  RECOGNIZED_METADATA: [
    'application_type',
    'client_id_issued_at',
    'client_id',
    'client_name',
    'client_secret_expires_at',
    'client_secret',
    'client_uri',
    'contacts',
    'default_acr_values',
    'default_max_age',
    'grant_types',
    'id_token_signed_response_alg',
    'initiate_login_uri',
    'jwks_uri',
    'jwks',
    'logo_uri',
    'policy_uri',
    'redirect_uris',
    'require_auth_time',
    'response_types',
    'sector_identifier_uri',
    'subject_type',
    'token_endpoint_auth_method',
    'tos_uri',
    'userinfo_signed_response_alg',
    'token_endpoint_auth_signing_alg',
    'introspection_endpoint_auth_method',
    'introspection_endpoint_auth_signing_alg',
    'introspection_signed_response_alg',
    'introspection_encrypted_response_alg',
    'introspection_encrypted_response_enc',
    'revocation_endpoint_auth_method',
    'revocation_endpoint_auth_signing_alg',
    'post_logout_redirect_uris',
    'backchannel_logout_session_required',
    'backchannel_logout_uri',
    'frontchannel_logout_session_required',
    'frontchannel_logout_uri',
    'request_object_signing_alg',
    'request_object_encryption_alg',
    'request_object_encryption_enc',
    'request_uris',
    'id_token_encrypted_response_alg',
    'id_token_encrypted_response_enc',
    'userinfo_encrypted_response_alg',
    'userinfo_encrypted_response_enc',
    'authorization_signed_response_alg',
    'authorization_encrypted_response_alg',
    'authorization_encrypted_response_enc',
    'web_message_uris'
  ],
  clientAdd: Function, // add
  clientRemove: Function, // remove
  Client: Function, // Client
  Session: Function, // Session,
  AccessToken: Function, // AccessToken]
  AuthorizationCode: Function, // AuthorizationCode,
  RefreshToken: Function, // RefreshToken],
  ClientCredentials: Function, // ClientCredentials],
  InitialAccessToken: Function, // InitialAccessToken],
  RegistrationAccessToken: Function, // RegistrationAccessToken],
  DeviceCode: Function, // DeviceCode],
  OIDCContext: Function, // OIDCContext],
  mountPath: '',
  initializing: true,
  keystore: {}, // typeof JWKStore
  Adapter: Function, // MemoryAdapter],
  router: { // typeof Koa Router
    opts: {},
    methods: ['HEAD', 'OPTIONS', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE'],
    params: {},
    stack: [{ // type Layer
      opts: {
        end: true,
        name: 'authorization',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'authorization',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // Async contextEnsureOidc
        Function, // Async ensureSessionSave
        Function, // Async authorizationErrorHandler
        Function, // Async noCache
        Function, // Async sessionHandler
        Function, // AsyncparseBodyIfPost
        Function, // Async assembleParams
        Function, // Async bound rejectDupes
        Function, // Async  checkClient
        Function, // Async oneRedirectUriClients
        Function, // Async
        Function, // Async checkResponseMode
        Function, // Async throwNotSupported
        Function, // Async oauthRequired
        Function, // Async checkOpenIdPresent
        Function, // Async: fetchRequestUri
        Function, // Async: decodeRequest
        Function, // Async: oidcRequired
        Function, // Async: checkPrompt
        Function, // Async: checkResponseType
        Function, // Async: checkScope
        Function, // Async: checkRedirectUri
        Function, // Async: checkWebMessageUri
        Function, // NOT Async checkResourceFormat
        Function, // Async: checkPixy
        Function, // Async: assignDefaults
        Function, // Async: checkClaims
        Function, // Async: authorizationEmit
        Function, // Async: assignClaims
        Function, // Async: loadAccount
        Function, // Async: interactions
        Function, // Async: respond
        Function // Async: processResponseTypes]
      ],
      path: '/auth',
      regexp: {
        /* /^\/auth(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'authorization',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'authorization',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // contextEnsureOidc
        Function, // ensureSessionSave
        Function, // authorizationErrorHandler
        Function, // noCache
        Function, // sessionHandler
        Function, // parseBodyIfPost]
        Function, // assembleParams
        Function, // : bound rejectDupes
        Function, // : checkClient
        Function, // : oneRedirectUriClients
        Function,
        Function, // checkResponseMode
        Function, // : throwNotSupported
        Function, // : oauthRequired
        Function, // : checkOpenIdPresent
        Function, // : fetchRequestUri
        Function, // : decodeRequest
        Function, // : oidcRequired
        Function, // : checkPrompt],
        Function, // : checkResponseType],
        Function, // : checkScope],
        Function, // : checkRedirectUri],
        Function, // : checkWebMessageUri],
        Function, // checkResourceFormat],  // NOT Async
        Function, // checkPixy],
        Function, // assignDefaults],
        Function, // checkClaims],
        Function, // authorizationEmit],
        Function, // assignClaims],
        Function, // loadAccount],
        Function, // : interactions],
        Function, // : respond],
        Function // : processResponseTypes]
      ],
      path: '/auth',
      regexp: {
        /* /^\/auth(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'resume',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'resume',
      methods: ['HEAD', 'GET'],
      paramNames: [
        Object
      ],
      stack: [
        Function, // : contextEnsureOidc]
        Function, // : ensureSessionSave],
        Function, // : authorizationErrorHandler],
        Function, // : noCache],
        Function, // : sessionHandler],
        Function, // : resumeAction],
        Function, // : bound rejectDupes],
        Function, // : checkClient],
        Function, // : authorizationEmit],
        Function, // : assignClaims],
        Function, // : loadAccount],
        Function, // : interactions],
        Function, // : respond],
        Function // : processResponseTypes]
      ],
      path: '/auth/:grant',
      regexp: {
        /* /^\/auth\/((?:[^\/]+?))(?:\/(?=$))?$/i */
        keys: [Array]
      }
    },
    {
      opts: {
        end: true,
        name: 'userinfo',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'userinfo',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : NOT Async cors],
        Function, // errorHandler],
        Function, // : noCache],
        Function, // : setWWWAuthenticateHeader],
        Function, // : parseBodyIfPost],
        Function, // : assembleParams],
        Function,
        Function, // : validateBearer],
        Function, // : validateScope],
        Function, // : loadClient],
        Function, // : loadAccount],
        Function // : respond]
      ],
      path: '/me',
      regexp: {
        /* /^\/me(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'userinfo',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'userinfo',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : NOT Async cors],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : setWWWAuthenticateHeader],
        Function, // : parseBodyIfPost],
        Function, // : assembleParams],
        Function,
        Function, // : validateBearer],
        Function, // : validateScope],
        Function, // : loadClient],
        Function, // : loadAccount],
        Function // : respond]
      ],
      path: '/me',
      regexp: {
        /* /^\/me(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'userinfo',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'userinfo',
      methods: ['OPTIONS'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function // NOT Async: cors]
      ],
      path: '/me',
      regexp: {
        /* /^\/me(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'token',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'token',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : selectiveBody],
        Function, // : assembleParams],
        Function, // : bound rejectDupes],
        Function, // : setWWWAuthenticateHeader],
        Function, // : findClientId],
        Function, // : loadClient],
        Function, // : auth],
        Function, // : bound rejectDupes],
        Function, // : stripGrantIrrelevantParams],
        Function, // NOT Async: checkResourceFormat],
        Function, // : supportedGrantTypeCheck],
        Function, // : allowedGrantTypeCheck],
        Function, // : implicitCheck],
        Function, // : rejectDupesOptionalExcept],
        Function // : callTokenHandler]
      ],
      path: '/token',
      regexp: {
        /* /^\/token(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'certificates',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'certificates',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : NOT Async cors],
        Function, // : errorHandler],
        Function // : renderCertificates]
      ],
      path: '/certs',
      regexp: {
        /* /^\/certs(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'certificates',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'certificates',
      methods: ['OPTIONS'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function // : Not Async cors]
      ],
      path: '/certs',
      regexp: {
        /* /^\/certs(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'registration',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'registration',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : setWWWAuthenticateHeader],
        Function, // : selectiveBody],
        Function, // : validateInitialAccessToken],
        Function // : registrationResponse]
      ],
      path: '/reg',
      regexp: {
        /* /^\/reg(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'client',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'client',
      methods: ['HEAD', 'GET'],
      paramNames: [
        Object
      ],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : setWWWAuthenticateHeader],
        Function, // : validateRegistrationAccessToken],
        Function // : clientReadResponse]
      ],
      path: '/reg/:clientId',
      regexp: {
        /* /^\/reg\/((?:[^\/]+?))(?:\/(?=$))?$/i */
        keys: [Array]
      }
    },
    {
      opts: {
        end: true,
        name: 'revocation',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'revocation',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : selectiveBody],
        Function, // : assembleParams],
        Function, // : bound rejectDupes],
        Function, // : setWWWAuthenticateHeader],
        Function, // : findClientId],
        Function, // : loadClient],
        Function, // : auth],
        Function,
        Function, // : validateTokenPresence],
        Function, // : renderTokenResponse],
        Function // : revokeToken]
      ],
      path: '/token/revocation',
      regexp: {
        /* /^\/token\/revocation(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'introspection',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'introspection',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : selectiveBody],
        Function, // : assembleParams],
        Function, // : bound rejectDupes],
        Function, // : setWWWAuthenticateHeader],
        Function, // : findClientId],
        Function, // : loadClient],
        Function, // : auth],
        Function,
        Function, // : validateTokenPresence],
        Function, // : debugOutput],
        Function, // : jwtIntrospectionResponse],
        Function // : renderTokenResponse]
      ],
      path: '/token/introspection',
      regexp: {
        /* /^\/token\/introspection(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'webfinger',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'webfinger',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : cors],
        Function, // : errorHandler],
        Function // : renderWebfingerResponse]
      ],
      path: '/.well-known/webfinger',
      regexp: {
        /* /^\/\.well-known\/webfinger(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'webfinger',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'webfinger',
      methods: ['OPTIONS'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function // : cors]
      ],
      path: '/.well-known/webfinger',
      regexp: {
        /* /^\/\.well-known\/webfinger(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'discovery',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'discovery',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : cors],
        Function, // : errorHandler],
        Function // : renderConfiguration]
      ],
      path: '/.well-known/openid-configuration',
      regexp: {
        /* /^\/\.well-known\/openid-configuration(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'discovery',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'discovery',
      methods: ['OPTIONS'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function // : cors]
      ],
      path: '/.well-known/openid-configuration',
      regexp: {
        /* /^\/\.well-known\/openid-configuration(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'check_session',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'check_session',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function // : checkSessionIframe]
      ],
      path: '/session/check',
      regexp: {
        /* /^\/session\/check(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'check_session_origin',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'check_session_origin',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : selectiveBody],
        Function, // : assembleParams],
        Function // : checkClientOrigin]
      ],
      path: '/session/check',
      regexp: {
        /* /^\/session\/check(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'end_session',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'end_session',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : sessionHandler],
        Function, // : assembleParams],
        Function,
        Function, // : endSessionChecks],
        Function // : renderLogout]
      ],
      path: '/session/end',
      regexp: {
        /* /^\/session\/end(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'end_session',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'end_session',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : sessionHandler],
        Function, // : parseBodyIfPost],
        Function, // : assembleParams],
        Function,
        Function, // : checkLogoutToken],
        Function // : endSession]
      ],
      path: '/session/end',
      regexp: {
        /* /^\/session\/end(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'device_authorization',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'device_authorization',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : parseBodyIfPost],
        Function, // : assembleParams],
        Function, // : bound rejectDupes],
        Function, // : checkClient],
        Function,
        Function, // NOT ASYNC: checkClientGrantType],
        Function, // : throwNotSupported],
        Function, // : checkParams],
        Function, // : fetchRequestUri],
        Function, // : decodeRequest],
        Function, // : checkPrompt],
        Function, // : checkScope],
        Function, // : checkResourceFormat],
        Function, // : checkPixy],
        Function, // : assignDefaults],
        Function, // : checkClaims],
        Function // : deviceAuthorizationResponse]
      ],
      path: '/device/auth',
      regexp: {
        /* /^\/device\/auth(?:\/(?=$))?$/i   */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'code_verification',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'code_verification',
      methods: ['HEAD', 'GET'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : sessionHandler],
        Function, // : assembleParams],
        Function // : renderCodeVerification]
      ],
      path: '/device',
      regexp: {
        /* /^\/device(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'code_verification',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'code_verification',
      methods: ['POST'],
      paramNames: [],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : sessionHandler],
        Function, // : parseBodyIfPost],
        Function, // : assembleParams],
        Function,
        Function, // : codeVerificationCSRF],
        Function, // : loadDeviceCodeByUserInput],
        Function, // : cleanup],
        Function, // : noCache],
        Function, // : deviceUserFlow],
        Function, // : bound rejectDupes],
        Function, // : checkClient],
        Function, // : authorizationEmit],
        Function, // : assignClaims],
        Function, // : loadAccount],
        Function, // : interactions],
        Function // : deviceVerificationResponse]
      ],
      path: '/device',
      regexp: {
        /* /^\/device(?:\/(?=$))?$/i */
        keys: []
      }
    },
    {
      opts: {
        end: true,
        name: 'device_resume',
        sensitive: false,
        strict: false,
        prefix: '',
        ignoreCaptures: undefined
      },
      name: 'device_resume',
      methods: ['HEAD', 'GET'],
      paramNames: [
        Object,
        Object
      ],
      stack: [
        Function, // : contextEnsureOidc],
        Function, // : ensureSessionSave],
        Function, // : errorHandler],
        Function, // : noCache],
        Function, // : sessionHandler],
        Function, // : resumeAction],
        Function, // : deviceUserFlow],
        Function, // : bound rejectDupes],
        Function, // : checkClient],
        Function, // : authorizationEmit],
        Function, // : assignClaims],
        Function, // : loadAccount],
        Function, // : interactions],
        Function // : deviceVerificationResponse]
      ],
      path: '/device/:user_code/:grant/',
      regexp: {
        /* /^\/device\/((?:[^\/]+?))\/((?:[^\/]+?))(?:\/(?=$))?$/i */
        keys: [Array]
      }
    }
    ]
  },
  initialized: true
}
