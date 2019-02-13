import https from 'https'
import http from 'http'
import qs from 'querystring'
// @ts-ignore
import rsa from 'jsrsasign'

let loginDetails = null as null | { token: string, sessionKeys: any, sessionState: any}

// Generic http(s) post
const postData = async (ssl: boolean, options: any, data: any) => {
  options.method = 'POST'
  return new Promise<[string, http.IncomingMessage]>((resolve, reject) => {
    // @ts-ignore
    const post_req = (ssl ? https : http).request(options, function(res: http.IncomingMessage) {
      const chunks: any[] = []
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        chunks.push(chunk)
      });
      res.on('end', () => {
        resolve([chunks.join(''), res])
      })
    })

    // post the data
    post_req.write(data)
    post_req.end()
  })
}
// Generic http(s) get
const getData = async (ssl: boolean, options: any) => {
  return new Promise<[string, http.IncomingMessage]>((resolve, reject) => {
    // @ts-ignore
    (ssl ? https : http).get(options, function(res: http.IncomingMessage) {
      const chunks: any[] = []
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        chunks.push(chunk)
      });
      res.on('end', () => {
        resolve([chunks.join(''), res])
      })
    })
  })
}
// Generate simple id
const makeid = (length: number) => {
  let text = ''
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'

  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length))
  }

  return text
}
// Generate session crypto
const generateSessionKeys = () => {
  const { prvKeyObj, pubKeyObj } = rsa.KEYUTIL.generateKeypair('RSA', 1024)
  const prvKeyJWK = rsa.KEYUTIL.getJWKFromKey(prvKeyObj)
  const pubKeyJWK = rsa.KEYUTIL.getJWKFromKey(pubKeyObj)

  return {
    prvKeyJWK,
    pubKeyJWK
  }
}

// Get OIDC config from Solid POD server
const getConfig = async (webid: string) => {
  const host = webid.split('/')[2]
  const provider = host.split('.').slice(1).join('.')

  const config = await getData(
    true, // Require ssl
    {
      host: provider,
      path: '/.well-known/openid-configuration'
    }
  ).then(([str, res]) => JSON.parse(str))

  const { issuer, jwks_uri, registration_endpoint, authorization_endpoint } = config

  // Return relevant values from the response
  return {
    issuer,
    jwksUri: jwks_uri,
    registrationEndpoint: registration_endpoint,
    authorizationEndpoint: authorization_endpoint
  }
}

// Get server signature verification keys
const getJWKS = async (jwksUri: string) => {
  const parts = jwksUri.split('/')
  const ssl = parts[0] === 'https:' // Check if using http or https
  const host = parts[2] // Get url host
  const path = '/' + parts.slice(3).join('/') // Get url path

  const { keys } = await getData(
    ssl,
    {
      host, path
    }
  ).then(([str, res]) => JSON.parse(str))
  
  // Return server signature verification keys
  return keys
}

// Register a client_id with the server
const registerClient = async (issuer: string, registrationEndpoint: string, callback: string) => {
  const parts = registrationEndpoint.split('/')
  const ssl = parts[0] === 'https:' // Check if using http or https
  const host = parts[2] // Get url host
  const path = '/' + parts.slice(3).join('/') // Get url path
  
  // Generate POST body
  const data = JSON.stringify({
    issuer,
    grant_types: ['implicit'],
    redirect_uris: [callback],
    response_types: ['id_token token'],
    scope: 'openid profile'
  })
  const { client_id } = await postData(
    ssl,
    {
      host,
      path,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    },
    data
  ).then(([str, res]) => {
    return JSON.parse(str)
  })

  // Return relevant parts of the response
  return { client_id }
}

// Login user with username/password
const loginUser = async (webid: string, password: string, pubKeyJWK: any, clientId: string, state: string, callback: string) => {
  const host = webid.split('/')[2] // Get url host from webid
  const username = host.split('.')[0] // Get username from host
  const provider = host.split('.').slice(1).join('.') // Get provider name from host

  // Generate login request
  const requestPart1 = Buffer.from(JSON.stringify({
    alg: 'none'
  })).toString('base64').replace(/=+$/, '')
  const requestPart2 = Buffer.from(JSON.stringify({
    redirect_uri: callback,
    display: 'page',
    nonce: makeid(64), // Generate nonce at random
    // Send previously generated session public key
    key: {
      alg: 'RS256',
      e: pubKeyJWK.e,
      ext: true,
      key_ops: ['verify'],
      kty: pubKeyJWK.kty,
      n: pubKeyJWK.n
    }
  })).toString('base64').replace(/=+$/, '')

  // Generate POST body
  const body = {
    username,
    password,
    response_type: 'id_token token',
    display: '',
    scope: 'openid',
    client_id: clientId,
    redirect_uri: callback,
    state,
    nonce: '',
    request: requestPart1 + '.' + requestPart2 + '.'
  }

  const data = qs.stringify(body)
  const response = await postData(
    true,
    {
      host: provider,
      path: '/login/password',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    },
    data
  ).then(([str, res]) => res)

  // Get redirect location from response header
  // (note: this only works with NodeJS as BrowserJS will automatically resolve the redirect and destroy these headers)
  const redirect = response.headers.location
  // Extract cookie
  const cookie = (response.headers['set-cookie'] || [])[0]

  // Return redirect/cookie combo
  return {
    redirect,
    cookie
  }
}

// Authenticate user
const authenticateUser = async (redirect: string, cookie: string) => {
  const parts = redirect.split('/')
  const ssl = parts[0] === 'https:' // Check if using http or https
  const host = parts[2] // Get url host
  const path = '/' + parts.slice(3).join('/') // Get url path

  // Manually resolve login redirect
  const authResponse = await getData(
    ssl,
    {
      host,
      path,
      headers: {
        Cookie: cookie
      }
    }
  ).then(([str, res]) => res)

  // Ensure redirect header exists
  if (!authResponse.headers.location) {
    return null
  }
  // Extract key/value pairs from redirect url hash component
  const urlHash = authResponse.headers.location.split('#')[1]
  const hashQuery = urlHash.split('&').reduce(
    (total: any, part: string) =>
      Object.assign(total, {
        [part.split('=')[0]]: part.split('=')[1]
      }),
    {}
  )
  const { token_type, id_token } = hashQuery

  // Return relevant data
  return {
    token_type,
    id_token
  }
}

// Generate JWT
const generateToken = async (tokenType: string, idToken: string, prvKeyJWK: any) => {
  // Parse claims
  const idClaims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString('utf8'))

  // Construct token header
  const JWTHeader = JSON.stringify({
    alg: 'RS256'
  })
  // Construct token header from auth response claims
  const JWTBody = JSON.stringify({
    iss: idClaims.aud,
    aud: idClaims.sub.split('/').slice(0, 3).join('/'),
    exp: idClaims.exp,
    iat: idClaims.iat,
    id_token: idToken,
    token_type: 'pop'
  })
  // Construct full token and sign with previously generated session private key
  const signedToken = rsa.KJUR.jws.JWS.sign(
    'RS256',
    JWTHeader,
    JWTBody,
    rsa.KEYUTIL.getKey(prvKeyJWK)
  )

  return `${tokenType} ${signedToken}`
}

const fullAuth = async (provider: string, username: string, password: string) => {
  // Construct webid
  const webid = `https://${username}.${provider}/profile/card#me`
  // Default callback
  const callback = 'http://localhost:8080'

  // Generate session crypto
  const sessionState = makeid(64)
  const sessionKeys = generateSessionKeys()
  
  // Get OIDC config from Solid POD server
  const config = await getConfig(webid)
  // Get Solid POD server keys for response verification
  const jwks = await getJWKS(config.jwksUri)
  // Register client with Solid POD server
  const register = await registerClient(config.issuer, config.registrationEndpoint, callback)
  // Log in to registered client_id
  const loginResponse = await loginUser(webid, password, sessionKeys.pubKeyJWK, register.client_id, sessionState, callback)
  if (!loginResponse.redirect) {
    throw new Error('Failed to log in with username/password')
  }
  // Authenticate user with cookie from login response
  const authResponse = await authenticateUser(loginResponse.redirect, loginResponse.cookie)
  if (!authResponse) {
    throw new Error('Error authenticating with server')
  }
  // Construct OIDC token from auth response
  const token = await generateToken(authResponse.token_type, authResponse.id_token, sessionKeys.prvKeyJWK)

  // Return
  loginDetails = {
    token,
    sessionKeys,
    sessionState
  }
}

// Get token and create if not exists
export const getToken = async (provider: string, username: string, password: string) => {
  if (!loginDetails) {
    await fullAuth(provider, username, password)
  }
  return loginDetails ? loginDetails.token : 'Failed to get token'
}