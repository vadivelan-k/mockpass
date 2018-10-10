const bodyParser = require('body-parser')
const fs = require('fs')
const morgan = require('morgan')
const { render } = require('mustache')
const path = require('path')
const { DOMParser } = require('xmldom')
const xpath = require('xpath')

const assertions = require('./assertions')
const crypto = require('./crypto')
const samlArtifact = require('./saml-artifact')

const domParser = new DOMParser()
const dom = xmlString => domParser.parseFromString(xmlString)

const TEMPLATE = fs.readFileSync(path.resolve(__dirname, '../static/saml/unsigned-response.xml'), 'utf8')

function config (app, { showLoginPage, serviceProvider, idpConfig }) {
  const { verifySignature, sign, promiseToEncryptAssertion } = crypto(serviceProvider)

  app.use(morgan('combined'))

  for (const idp of ['singPass', 'corpPass']) {
    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const relayState = encodeURIComponent(req.query.Target)
      const samlArt = samlArtifact(idpConfig[idp].id)
      const assertURL =
        `${idpConfig[idp].assertEndpoint}?SAMLart=${samlArt}&RelayState=${relayState}`
      console.warn(`Redirecting login from ${req.query.PartnerId} to ${assertURL}`)
      if (showLoginPage) {
        res.send(`
          <html>
            <body>
            <form action="${idpConfig[idp].assertEndpoint}" method="get"><select name="SAMLart" style="width: 100%; display: block; font-size: 32px"><option value="S1234567A">S1234567A</option><option value="S1234567B">S1234567B</option><option value="S1234567C">S1234567C</option><option value="S1234567D">S1234567D</option><option value="S1234567E">S1234567E</option><option value="S1234567F">S1234567F</option></select><button autofocus="" style="margin-top: 10px;  width:100%; display: block; height:80px; font-size: 20px" type="submit">Login</button></form>
            <form action="${idpConfig[idp].assertEndpoint}" method="get"><h6>Login with your own user</h6><input maxlength="9" name="SAMLart" placeholder="NRIC" style="margin-right: 5px; font-size: 32px" value="S0862994C"><button autofocus="" type="submit">Login</button></form>
            </body>
          </html>
        `)
      } else {
        res.redirect(assertURL)
      }
    })

    app.post(
      `/${idp.toLowerCase()}/soap`,
      bodyParser.text({ type: 'text/xml' }),
      (req, res) => {
        // Extract the body of the SOAP request
        const { body } = req
        const xml = dom(body)

        if (!verifySignature(xml)) {
          res.status(400).send('Request has bad signature')
        } else {
          // Grab the SAML artifact
          // TODO: verify the SAML artifact is something we sent
          // TODO: do something about the partner entity id
          const samlArtifact = xpath.select("string(//*[local-name(.)='Artifact'])", xml)
          console.warn(`Received SAML Artifact ${samlArtifact}`)
          // Take the template and plug in the typical SingPass/CorpPass response
          // Sign and encrypt the assertion
          const idpAssertion = assertions.mergeValuesIntoAssertionTemplate(
            { idpType: idp, nric: samlArtifact }
          );
          promiseToEncryptAssertion(
            sign(idpAssertion, "//*[local-name(.)='Assertion']")
          ).then(assertion => {
            const response = render(TEMPLATE, {
              assertion: assertion,
              assertEndpoint: process.env.SINGPASS_ASSERT_ENDPOINT || 'http://sp.example.com/demo1/index.php?acs'
            })
            const signedResponse = sign(
              sign(response, "//*[local-name(.)='Response']"),
              "//*[local-name(.)='ArtifactResponse']"
            )
            res.send(signedResponse)
          })
        }
      }
    )
  }
  return app
}

module.exports = { config }
