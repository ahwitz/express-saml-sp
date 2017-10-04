var _ = require("underscore");
var xpath = require('xpath');
var xmldom = require('xmldom');
var xmlenc = require('xml-encryption');

var samlSelect = xpath.useNamespaces({
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol"
});

class ServiceProvider
{
    constructor(options)
    {
        var valid = this.validateOptions(options);
        if (!valid) return;

        this.metadataTemplate = _.template(options.metadataTemplate);
        this.compiledTemplate = this.metadataTemplate(options.metadataConfig);
        this.certPrivateKey = options.certPrivateKey;

        // Filled in later
        this.decryptedXML;

        this.initWrappers();
    }

    samlMetadata(req, res)
    {
        res.status(200);
        res.type('application/xml');
        res.send(this.compiledTemplate);
    }

    samlResponse(req, res, next)
    {
        var xml = new Buffer(req.body.SAMLResponse, 'base64').toString('utf8');
        var doc = new xmldom.DOMParser().parseFromString(xml);

        /**
         * Get issuer
         */
        var issuer = getIssuerFromDoc(doc);
        if (!issuer)
        {
            const err = "Could not find a valid Issuer within SAML response. Quitting.";
            res.status(400, "Bad Request");
            res.send(err + "\n");
            console.error(err);
            return;
        }

        /**
         * Decrypt XML
         */
        var xmlPromise = getDecryptedXML(doc, this);

        var self = this;
        Promise.all([xmlPromise]).then(function()
        {
            req.samlResponse = self.decryptedXML.toString();
            next();
        }).catch(function(err)
        {
            console.log("failed with", err);
            req.samlResponse = null;
            next();
        });
    }

    validateOptions(options)
    {
        if (!options)
        {
            console.error("ServiceProvider class must be instantiated with an options object.");
            return false;
        }
        if (!('metadataTemplate' in options))
        {
            console.error("ServiceProvider class must be instantiated with metadataTemplate option.");
            return false;
        }
        if (!('metadataConfig' in options))
        {
            console.error("ServiceProvider class not instantiated with metadataConfig option.");
        }

        if (!('certPrivateKey' in options))
        {
            console.warn("ServiceProvider class not instantiated with certPrivateKey option - treating all incoming responses as unencrypted.");
        }

        return true;
    }

    /**
     * Required to properly scope all Express functions within this object
     */
    initWrappers()
    {
        const self = this;
        this.samlMetadataHandler = function(req, res)
        {
            self.samlMetadata.apply(self, [req, res]);
        };

        this.samlResponseParser = function(req, res, next)
        {
            self.samlResponse.apply(self, [req, res, next]);
        };
    }
}

function getIssuerFromDoc (doc)
{
    var issuerNode = samlSelect("/saml2p:Response/saml2:Issuer/text()", doc);
    return (issuerNode && issuerNode.length > 0) ? issuerNode[0].nodeValue : false;
}

function getDecryptedXML (doc, context)
{
    return new Promise(function(resolve, reject)
    {
        var encryptedAssertions = samlSelect("//saml2:EncryptedAssertion", doc);
        // If it is encrypted
        if (encryptedAssertions && encryptedAssertions.length > 0)
        {
            xmlenc.decrypt(encryptedAssertions[0].toString(), {
                key: context.certPrivateKey
            }, function (err, res) {
                if (err || !res)
                {
                    console.error(err);
                    reject("Error decrypting XML.");
                }
                else
                {
                    let assertionNode = new xmldom.DOMParser().parseFromString(res);
                    doc.replaceChild(assertionNode, encryptedAssertions[0]);
                    context.decryptedXML = doc;
                    resolve();
                }
            });
        }
        // No encrypted assertions
        else 
        {
            context.decryptedXML = doc;
            resolve();
        }
    });
}

module.exports.ServiceProvider = ServiceProvider;