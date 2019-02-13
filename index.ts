import { getToken } from './authenticate'

const provider = process.env.SOLID_PROVIDER || ''
const username = process.env.SOLID_USER || ''
const password = process.env.SOLID_PASS || ''

console.log(` [*] Logging in to https://${username}.${provider}/profile/card#me (p: ${password})`)

getToken(provider, username, password).then((token) => {
  console.log(' [\u2713] Got Token:', token)
})