using CDR.Register.API.Infrastructure.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CDR.Register.Admin.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LoopbackController : Controller
    {

        private readonly IConfiguration _config;

        public LoopbackController(IConfiguration config)
        {
            _config = config;
        }

        /// <summary>
        /// This controller action provides an implementation of a JWKS for a Mock Data Recipient.
        /// </summary>
        /// <returns>JWKS</returns>
        [HttpGet]
        [Route("MockDataRecipientJwks")]
        [ServiceFilter(typeof(LogActionEntryAttribute))]
        public IActionResult MockDataRecipientJwks()
        {
            var cert = new X509Certificate2("Certificates/client.pem");
            var x5cStr = "MIIEoTCCAomgAwIBAgIJAOq6p0K1g1nHMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNV" +
                "BAYTAkFVMQwwCgYDVQQIDANBQ1QxETAPBgNVBAcMCENhbmJlcnJhMQ0wCwYDVQQK" +
                "DARBQ0NDMQwwCgYDVQQLDANDRFIxFDASBgNVBAMMC01vY2sgQ0RSIENBMB4XDTIy" +
                "MDUyMzA0Mjc0MFoXDTIzMDYyNzA0Mjc0MFowZzEaMBgGA1UEAwwRTW9ja0RhdGFS" +
                "ZWNpcGllbnQxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANBQ1QxETAPBgNVBAcMCENh" +
                "bmJlcnJhMQ0wCwYDVQQKDARBQ0NDMQwwCgYDVQQLDANDRFIwggEiMA0GCSqGSIb3" +
                "DQEBAQUAA4IBDwAwggEKAoIBAQCzoH/1TK63z+axsPAbE1LUzBJAK3RZlY91t7Cr" +
                "EmjkUU+U9ivJStZIkLaJIOlj4IDb5rFtkiGeO6PGtIm1tGLNdG8ZvqIHKdc20y/n" +
                "0kCzMQKYe6OUhg3xrmkt4b8V/lidnV3l/tc0a4OPAoPhu1/etBN/3juowfV0VoY0" +
                "DXmkUzAxICsqxNR18bRT+zI0EuNQBDhJkPYk6mvHt0UY5U9aD5rrjiei1kJLrQ3a" +
                "p0IrWbe1HKQ4q5TjXWsxg8nywUZqeR3Rs0SAAz3WOpEEdFjAGLSYmltMHKPXE6oJ" +
                "jmfWqsVAOao7BeAdCBdyCk0oupXo0XKMY4s1mI6616Rq7EzbAgMBAAGjVjBUMB8G" +
                "A1UdIwQYMBaAFIMGntq6COYrCVIIYmzeFKQXdnVRMAkGA1UdEwQCMAAwDgYDVR0P" +
                "AQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUA" +
                "A4ICAQBBXWAvnMkDk+kzS8NLVEgwhGhwvDSrqKuDML14cAYWGPuMuVZ+HvuVX0qO" +
                "mCXqyk7qhClofmUDxgrJ041I/0iox8oDqKM2kxlLpwktDYFqnS23XOiVNL3YNdxU" +
                "fyJWLMZCrb+cjidEGaPku4HPH4/H0o7sRji966zOw48tArtN/VBFJz0g7O6cT2yM" +
                "HFxbkTLvL/+ZO1FxS7YvjEhxPjsyt+M4eXrj2HCAsCQTVWXJwjtizxhrBRfElaR2" +
                "Og6vQhIxgC+PUrkbWLPegFQAC5XhZ3Y5kJVmZUXEqDD4vi/VuGSyjBd2+c2IcK71" +
                "JFOgO6pqiIGAt9Inx1EgTENG8IzannjXaoXGkj9x3ugE5H54a8B4ZuDoODsKSrJ/" +
                "RmmWRZqKeLTVIIdMt6Tyjk4w7tQ5Qv+3xmh37qrRmhdT3grmuPVQtl7+Blwcg4Zz" +
                "oJVUxrId/UPg74cfdIF7lhKVfrT0UUaitwBvXHaE33hzyHbvlmQnIT94nhVZg317" +
                "A7X3vsK90v7xjQq7mLWw9E83TDlXf/08qJXPwUe2BoLvVcVd5ouUapoXw+6zv8me" +
                "dl5IrE54qD62RUbP61f/dlROcS0i7nVEfjbwHFh16C9uOgnHt8mqq0dWFQvmlqlf" +
                "oE/EgVB5O6TfoVNiQbXA7E6Pc0WC/WUFvyzJ0HYHiDOZc16P9Q==";
            var key = cert.GetRSAPublicKey();
            var rsaParams = key.ExportParameters(false);
            var kid = GenerateKid(rsaParams, out var e, out var n);
            var jwk1 = new CDR.Register.API.Infrastructure.Models.JsonWebKey()
            {
                alg = "PS256",
                kid = kid,
                kty = "RSA",
                n = n,
                e = e,
                key_ops = new string[] { "sign", "verify" },
                use = "sig",
                x5c = new string[] { x5cStr },
                x5t = "UYsSYQtcB7cLVTSjtn0kIBxlthY"
            };
            var jwk2 = new CDR.Register.API.Infrastructure.Models.JsonWebKey()
            {
                alg = "RSA-OAEP",
                kid = kid,
                kty = "RSA",
                n = n,
                e = e,
                key_ops = new string[] { "sign", "verify" },
                use = "enc",
                x5c = new string[] { x5cStr },
                x5t = "UYsSYQtcB7cLVTSjtn0kIBxlthY"
            };
            var jwk3 = new CDR.Register.API.Infrastructure.Models.JsonWebKey()
            {
                alg = "A256GCM",
                kid = kid,
                kty = "RSA",
                n = n,
                e = e,
                key_ops = new string[] { "sign", "verify" },
                use = "enc",
                x5c = new string[] { x5cStr },
                x5t = "UYsSYQtcB7cLVTSjtn0kIBxlthY"
            };
            return Ok(new CDR.Register.API.Infrastructure.Models.JsonWebKeySet()
            {
                keys = new CDR.Register.API.Infrastructure.Models.JsonWebKey[] { jwk1,jwk2,jwk3 }
            });
        }

        /// <summary>
        /// This controller action produces a client assertion for a mock data recipient.
        /// </summary>
        /// <returns>Client assertion string</returns>
        /// <remarks>
        /// This client assertion can then be used in a private key jwt request.
        /// </remarks>
        [HttpGet]
        [Route("MockDataRecipientClientAssertion")]
        [ServiceFilter(typeof(LogActionEntryAttribute))]
        public IActionResult MockDataRecipientClientAssertion()
        {
            var privateKeyRaw = System.IO.File.ReadAllText("Certificates/client.key");
            var privateKey = privateKeyRaw.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r\n", "").Trim();
            var privateKeyBytes = Convert.FromBase64String(privateKey);

            string audience = _config.GetValue<string>("IdentityServerTokenUri") ?? "https://localhost:7001/idp/connect/token";
            string softwareProductId = _config.GetValue<string>("LoopbackDefaultSoftwareProductId") ?? "6F7A1B8E-8799-48A8-9011-E3920391F713";
            if (Request.Query.TryGetValue("iss", out var iss))
            {
                softwareProductId = iss.ToString();
            }

            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                var kid = GenerateKid(rsa);
                var privateSecurityKey = new RsaSecurityKey(rsa)
                {
                    KeyId = kid,
                    CryptoProviderFactory = new CryptoProviderFactory()
                    {
                        CacheSignatureProviders = false
                    }
                };

                var descriptor = new SecurityTokenDescriptor
                {
                    Issuer = softwareProductId,
                    Audience = audience,
                    Expires = DateTime.UtcNow.AddMinutes(10),
                    Subject = new ClaimsIdentity(new List<Claim> { new Claim("sub", softwareProductId) }),
                    SigningCredentials = new SigningCredentials(privateSecurityKey, SecurityAlgorithms.RsaSsaPssSha256),
                    NotBefore = null,
                    IssuedAt = null,
                    Claims = new Dictionary<string, object>()
                };
                descriptor.Claims.Add("jti", Guid.NewGuid().ToString());

                var tokenHandler = new JsonWebTokenHandler();
                return new OkObjectResult(tokenHandler.CreateToken(descriptor));
            }
        }

        /// <summary>
        /// This controller action produces a self signed JWT for the mock register.
        /// </summary>
        /// <returns>Self Signed JWT</returns>
        [HttpGet]
        [Route("RegisterSelfSignedJwt")]
        [ServiceFilter(typeof(LogActionEntryAttribute))]
        public IActionResult RegisterSelfSignedJwt(
            [FromQuery] string aud)
        {
            var cert = new X509Certificate2(_config.GetValue<string>("SigningCertificate:Path"), _config.GetValue<string>("SigningCertificate:Password"), X509KeyStorageFlags.Exportable);            
            var signingCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSsaPssSha256);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "cdr-register",
                Subject = new ClaimsIdentity(new List<Claim> { new Claim("sub", "cdr-register") }),
                Audience = aud,
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = signingCredentials,
                NotBefore = null,
                IssuedAt = DateTime.UtcNow,
                Claims = new Dictionary<string, object>()
            };
            descriptor.Claims.Add("jti", Guid.NewGuid().ToString());

            var tokenHandler = new JsonWebTokenHandler();
            return new OkObjectResult(tokenHandler.CreateToken(descriptor));
        }

        private static string GenerateKid(RSA rsa)
        {
            var rsaParameters = rsa.ExportParameters(false);
            return GenerateKid(rsaParameters, out _, out _);
        }

        private static string GenerateKid(RSAParameters rsaParams, out string e, out string n)
        {
            e = Base64UrlEncoder.Encode(rsaParams.Exponent);
            n = Base64UrlEncoder.Encode(rsaParams.Modulus);
            var dict = new Dictionary<string, string>() {
                {"e", e},
                {"kty", "RSA"},
                {"n", n}
            };
            var hash = SHA256.Create();
            var hashBytes = hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
            return Base64UrlEncoder.Encode(hashBytes);
        }
    }
}