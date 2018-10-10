const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')

const readFrom = p => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const NRIC = process.env.MOCKPASS_NRIC || 'S8979373D'
const UEN = process.env.MOCKPASS_UEN || '123456789A'
const assertEndpoint = process.env.SINGPASS_ASSERT_ENDPOINT || 'http://sp.example.com/demo1/index.php?acs'
const serviceProviderEntityId = process.env.SINGPASS_ENTITY_ID || 'http://sp.example.com/demo1/metadata.php'

const CORPPASS = base64.encode(render(corpPassTemplate, { NRIC, UEN }))

const mergeValuesIntoAssertionTemplate = ({ idpType, nric, uen, corpPassXml }) => {
  const templateOption = idpType === 'singPass' ?
  { name: 'UserName', value: nric, assertEndpoint, serviceProviderEntityId }
  :
  { name: uen, value: corpPassXml || CORPPASS, assertEndpoint, serviceProviderEntityId };

  return render(TEMPLATE, templateOption);
}

module.exports = {
  mergeValuesIntoAssertionTemplate: mergeValuesIntoAssertionTemplate
}
