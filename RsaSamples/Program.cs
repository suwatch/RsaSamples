using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace RsaSamples
{
    class Program
    {
        // done id_rsa (pem) => RSACryptoServiceProvider
        // done id_rsa.pub (openssh) => RSACryptoServiceProvider
        // done priv RSACryptoServiceProvider => id_rsa (pem)
        // done priv RSACryptoServiceProvider => id_rsa.pem (pem)
        // done priv RSACryptoServiceProvider => id_rsa.pub (openssh)

        static void Main(string[] args)
        {
            // ssh-keygen -t rsa -C "suwatch@microsoft.com"
            var privPemFile = @"c:\temp\id_rsa_test";
            var pubSSHFile = @"c:\temp\id_rsa_test.pub";
            var pubPemFile = @"c:\temp\temp.pem";

            // ssh-keygen -f c:\temp\id_rsa_test.pub -e -m pem > id_rsa_test1.pem
            // var pubPem1File = @"c:\temp\id_rsa_test1.pem";
            //  "c:\Program Files\Git\usr\bin\openssl.exe" rsa -in c:\temp\id_rsa_test -pubout > id_rsa_test2.pem
            var pubPem2File = @"c:\temp\id_rsa_test2.pem";

            try
            {
                // id_rsa (pem) => RSACryptoServiceProvider
                var rsaPri = PemKeyUtils.GetRSAProviderFromPemFile(privPemFile);
                //Console.WriteLine(rsaPri);

                TestSSHKeyGen();

                var cer = new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQbiJkXaenk61AKixVocnLRTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTAwNTAwMDAwMFoXDTI0MTAwNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2H9Y6Z+3BXUCtlbmXr6H5owYy15XTl3vdpOZLUkk4OV9LMsB1phjNp+wgl28eAgrNNfu4BTVlHdR9x6NTrSiIapsYjzzEz4mOmRh1Bw5tJxit0VEGn00/ZENniTjgeEFYgDHYwjrfZQ6dERBFiw1OQb2IG5f3KLtx92lUXeIZ7ZvTaPkUpc4Qd6wQZmWgzPqWFocRsJATGyZzXiiXQUrc9cVqm1bws3P0lFBcqNtv+AKDYKT5IRYLsyCkueQC9R6LUCsZVD7bVIkeQuA3iehJKIEAlk/e3j5E4VaCRs642ajb/z9kByTl2xL2k0AeZGc8/Rcy7SQn0LBcJNZGp/SMCAwEAAaMhMB8wHQYDVR0OBBYEFOLhl3BDPLNVYDe38Dp9JbUmd4kKMA0GCSqGSIb3DQEBCwUAA4IBAQAN4XwyqYfVdMl0xEbBMa/OzSfIbuI4pQWWpl3isKRAyhXezAX1t/0532LsIcYkwubLifnjHHqo4x1jnVqkvkFjcPZ12kjs/q5d1L0LxlQST/Uqwm/9/AeTzRZXtUKNBWBOWy9gmw9DEH593sNYytGAEerbWhCR3agUxsnQSYTTwg4K9cSqLWzHX5Kcz0NLCGwLx015/Jc7HwPJnp7q5Bo0O0VfhomDiEctIFfzqE5x9T9ZTUSWUDn3J7DYzs2L1pDrOQaNs/YEkXsKDP1j4tOFyxic6OvjQ10Yugjo5jg1uWoxeU8pI0BxY6sj2GZt3Ynzev2bZqmj68y0I9Z+NTZo"));
                var jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyIsImtpZCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNTc1Nzk1NjkzLCJuYmYiOjE1NzU3OTU2OTMsImV4cCI6MTU3NTc5OTU5MywiX2NsYWltX25hbWVzIjp7Imdyb3VwcyI6InNyYzEifSwiX2NsYWltX3NvdXJjZXMiOnsic3JjMSI6eyJlbmRwb2ludCI6Imh0dHBzOi8vZ3JhcGgud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3VzZXJzL2E2MjA2MGRhLTFhZTMtNDRlYi04OTg4LTExOTdhNjhmZjQxZS9nZXRNZW1iZXJPYmplY3RzIn19LCJhY3IiOiIxIiwiYWlvIjoiQVZRQXEvOE5BQUFBOG9wTC83SkV1aUc5U1ZNTGkvb0VLWktFY3JUS1VkUi9GUXlmTUl3NjhQN211QmtKeFV3Q1RnbHpxQWtETlEvaG1ZSmVoNk9RcUdQNDZZVlhJKzNZeFAySWt2QUhNNnFLQVNvNmdybWVMUzQ9IiwiYW1yIjpbIndpYSIsIm1mYSJdLCJhcHBpZCI6IjE5NTBhMjU4LTIyN2ItNGUzMS1hOWNmLTcxNzQ5NTk0NWZjMiIsImFwcGlkYWNyIjoiMCIsImRldmljZWlkIjoiZjE4MDEyZTQtOWQzZC00ZjBmLWFjNjMtM2RjMDMzMGEzNjQ2IiwiZmFtaWx5X25hbWUiOiJCb2RpbiIsImdpdmVuX25hbWUiOiJTdXdhdCIsImlwYWRkciI6IjEzMS4xMDcuMTQ3LjYzIiwibmFtZSI6IlN1d2F0IEJvZGluIiwib2lkIjoiYTYyMDYwZGEtMWFlMy00NGViLTg5ODgtMTE5N2E2OGZmNDFlIiwib25wcmVtX3NpZCI6IlMtMS01LTIxLTIxMjc1MjExODQtMTYwNDAxMjkyMC0xODg3OTI3NTI3LTY3NTU3IiwicHVpZCI6IjEwMDMwMDAwODAxQzIwRDQiLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJVdHoxNlRBODE4bURtQ3dvNDhKLUdsZlFtdTN1T0VEcmgtMWFqQndlOEw0IiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJzdXdhdGNoQG1pY3Jvc29mdC5jb20iLCJ1cG4iOiJzdXdhdGNoQG1pY3Jvc29mdC5jb20iLCJ1dGkiOiIteVhESHl4UVQwMllNVWpLcXNjaEFBIiwidmVyIjoiMS4wIn0.Vw9lr708WLmJAVcyz9mhLjHpblBviwGKnqJJR-HbcMgGN-P37vFUrpzOSi254Zoy3jjHuZsRh5i2AXRxYqTrADyJMRjr7y4DB_waJQ9O49dN9W_qpKFZBkTkr3ZE6j_wIoUH-6D8xFMtMcbMTVVJn9JWq23sgWgr4DUw-qC1sU_1RfsqvwFlCsrjcZZdvN5PiM7TTXjlUEbThmUG1gmxTORjlCrsS6KG7t5Smj4ycZQMCy6Ds26cw-wL6Y2vXKdiON9nknlvUwrsK2kxhR5e4SI91A33PeqEmqXlxpxMp630nyk5RMBd_4tCnkEDlZet5L_MNPeZsasdAUssjdDh5A";
                var validated = ValidateToken(jwt, new X509SecurityKey(cer));
                Console.WriteLine(validated);
                validated = ValidateToken2(jwt, new X509SecurityKey(cer));
                Console.WriteLine(validated);


                // not working BEGIN RSA PUBLIC KEY!!
                // var rsaPub_1 = PemKeyUtils.GetRSAProviderFromPemFile(pubPem1File);
                var rsaPub_2 = PemKeyUtils.GetRSAProviderFromPemFile(pubPem2File);

                jwt = GenerateJWT(rsaPri);
                validated = ValidateToken(jwt, new RsaSecurityKey(rsaPri));
                Console.WriteLine(validated);
                validated = ValidateToken2(jwt, new RsaSecurityKey(rsaPub_2));
                Console.WriteLine(validated);

                // "c:\Program Files\Git\usr\bin\openssl.exe" rsa -pubin -in c:\temp\temp.pem -text -noout
                // priv RSACryptoServiceProvider => id_rsa (pem)
                // TODO, suwatch:
                var privPem = RSAKeys.ExportPrivateKey(rsaPri);
                Console.WriteLine(privPem == File.ReadAllText(privPemFile));
                //Console.WriteLine(File.ReadAllText(privPemFile));
                //Console.WriteLine(privPem);

                var pubPem = PemKeyUtils.ExportPublicKey(rsaPri);
                Console.WriteLine(pubPem == File.ReadAllText(pubPemFile));
                //Console.WriteLine(pub);
                //File.WriteAllText(pubPemFile, pubPem);

                var rsaPub = PemKeyUtils.GetRSAProviderFromPemFile(pubPemFile);
                //Console.WriteLine(rsaPub);

                // priv RSACryptoServiceProvider => id_rsa.pub (openssh)
                var id_rsa_pub = PemKeyUtils.ExportPublicKeySSH(rsaPub);
                Console.WriteLine(id_rsa_pub == File.ReadAllText(pubSSHFile));
                //Console.WriteLine("'" + id_rsa_pub + "'");
                //Console.WriteLine("'" + File.ReadAllText(pubSSHFile) + "'");

                var privParams = rsaPri.ExportParameters(includePrivateParameters: false);
                var pubParams = rsaPub.ExportParameters(includePrivateParameters: false);

                // id_rsa.pub (openssh) => RSACryptoServiceProvider
                var rsaPub1 = PemKeyUtils.FromOpenSSHFile(pubSSHFile);
                var pub1Params = rsaPub1.ExportParameters(includePrivateParameters: false);

                // Modulus and exponent represent Public component
                //Console.WriteLine(Convert.ToBase64String(privParams.Exponent));
                //Console.WriteLine(Convert.ToBase64String(privParams.Modulus));
                Console.WriteLine(Convert.ToBase64String(privParams.Exponent) == Convert.ToBase64String(pubParams.Exponent));
                Console.WriteLine(Convert.ToBase64String(privParams.Modulus) == Convert.ToBase64String(pubParams.Modulus));
                Console.WriteLine(Convert.ToBase64String(privParams.Exponent) == Convert.ToBase64String(pub1Params.Exponent));
                Console.WriteLine(Convert.ToBase64String(privParams.Modulus) == Convert.ToBase64String(pub1Params.Modulus));

                var text = Guid.NewGuid().ToString();
                var signature = SignRS256(text, rsaPri);
                var verified = VerifyRS256(text, signature, rsaPub);
                Console.WriteLine(verified);

                verified = VerifyRS256(text, signature, rsaPub1);
                Console.WriteLine(verified);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static void TestSSHKeyGen()
        {
            var rsa = new RSACryptoServiceProvider(256 * 8);

            var sshRsa = PemKeyUtils.ExportPublicKeySSH(rsa);
            Console.WriteLine(sshRsa);

            var privPem = RSAKeys.ExportPrivateKey(rsa);
            Console.WriteLine(privPem);
        }

        static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            // JWT pass as header need to url encode/decode
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        static string Base64UrlEncode(byte[] arg, int offset, int length)
        {
            string s = Convert.ToBase64String(arg, offset, length); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            // JWT pass as header need to url encode/decode
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        static byte[] Base64UrlDecode(string arg)
        {
            string s = arg;
            // JWT pass as header need to url encode/decode
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception( "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        static bool ValidateToken(string id_token, params SecurityKey[] signingKeys)
        {
            var parts = id_token.Split('.');
            // {"typ":"JWT","alg":"RS256","x5t":"BB8CeFVqyaGrGNuehJIiL4dfjzw","kid":"BB8CeFVqyaGrGNuehJIiL4dfjzw"}
            var header = JObject.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[0])));
            // {"aud":"https://management.core.windows.net/","iss":"https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/","iat":1575791738,"nbf":1575791738,"exp":1575795638,"_claim_names":{"groups":"src1"},"_claim_sources":{"src1":{"endpoint":"https://graph.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/users/a62060da-1ae3-44eb-8988-1197a68ff41e/getMemberObjects"}},"acr":"1","aio":"AVQAq/8NAAAA0NQC8jkv1YNUiGii8tr38nUIzxaOGEFwRiAVnU1QiGe5Ih5YMgYD2zkZ23+PPQx8dfcyBZ3V3EV5pUlrs0UejS2ei/o7OFbHJuLyeM4uOq8=","amr":["wia","mfa"],"appid":"1950a258-227b-4e31-a9cf-717495945fc2","appidacr":"0","deviceid":"f18012e4-9d3d-4f0f-ac63-3dc0330a3646","family_name":"Bodin","given_name":"Suwat","in_corp":"true","ipaddr":"131.107.159.63","name":"Suwat Bodin","oid":"a62060da-1ae3-44eb-8988-1197a68ff41e","onprem_sid":"S-1-5-21-2127521184-1604012920-1887927527-67557","puid":"10030000801C20D4","scp":"user_impersonation","sub":"Utz16TA818mDmCwo48J-GlfQmu3uOEDrh-1ajBwe8L4","tid":"72f988bf-86f1-41af-91ab-2d7cd011db47","unique_name":"suwatch@microsoft.com","upn":"suwatch@microsoft.com","uti":"H_HhFZSIGkeQUM1BYOghAA","ver":"1.0"}
            var payload = JObject.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[1])));
            var signature = Base64UrlDecode(parts[2]);

            //X509Certificate2 cer = new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQbiJkXaenk61AKixVocnLRTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTAwNTAwMDAwMFoXDTI0MTAwNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2H9Y6Z+3BXUCtlbmXr6H5owYy15XTl3vdpOZLUkk4OV9LMsB1phjNp+wgl28eAgrNNfu4BTVlHdR9x6NTrSiIapsYjzzEz4mOmRh1Bw5tJxit0VEGn00/ZENniTjgeEFYgDHYwjrfZQ6dERBFiw1OQb2IG5f3KLtx92lUXeIZ7ZvTaPkUpc4Qd6wQZmWgzPqWFocRsJATGyZzXiiXQUrc9cVqm1bws3P0lFBcqNtv+AKDYKT5IRYLsyCkueQC9R6LUCsZVD7bVIkeQuA3iehJKIEAlk/e3j5E4VaCRs642ajb/z9kByTl2xL2k0AeZGc8/Rcy7SQn0LBcJNZGp/SMCAwEAAaMhMB8wHQYDVR0OBBYEFOLhl3BDPLNVYDe38Dp9JbUmd4kKMA0GCSqGSIb3DQEBCwUAA4IBAQAN4XwyqYfVdMl0xEbBMa/OzSfIbuI4pQWWpl3isKRAyhXezAX1t/0532LsIcYkwubLifnjHHqo4x1jnVqkvkFjcPZ12kjs/q5d1L0LxlQST/Uqwm/9/AeTzRZXtUKNBWBOWy9gmw9DEH593sNYytGAEerbWhCR3agUxsnQSYTTwg4K9cSqLWzHX5Kcz0NLCGwLx015/Jc7HwPJnp7q5Bo0O0VfhomDiEctIFfzqE5x9T9ZTUSWUDn3J7DYzs2L1pDrOQaNs/YEkXsKDP1j4tOFyxic6OvjQ10Yugjo5jg1uWoxeU8pI0BxY6sj2GZt3Ynzev2bZqmj68y0I9Z+NTZo"));
            //Console.WriteLine($"\"x5c\" : \"{Base64UrlEncode(cer.GetCertHash())}\"");
            //var cerRsa = cer.GetRSAPublicKey();
            //var cerCsp = cerRsa.ExportParameters(includePrivateParameters: false);
            //Console.WriteLine($"\"n\" : \"{Base64UrlEncode(cerCsp.Modulus)}\"");
            //Console.WriteLine($"\"e\" : \"{Base64UrlEncode(cerCsp.Exponent)}\"");
            //var exponent = Base64UrlDecode("AQAB");
            //var modulus = Base64UrlDecode("nYf1jpn7cFdQK2VuZevofmjBjLXldOXe92k5ktSSTg5X0sywHWmGM2n7CCXbx4CCs01-7gFNWUd1H3Ho1OtKIhqmxiPPMTPiY6ZGHUHDm0nGK3RUQafTT9kQ2eJOOB4QViAMdjCOt9lDp0REEWLDU5BvYgbl_cou3H3aVRd4hntm9No-RSlzhB3rBBmZaDM-pYWhxGwkBMbJnNeKJdBStz1xWqbVvCzc_SUUFyo22_4AoNgpPkhFguzIKS55AL1HotQKxlUPttUiR5C4DeJ6EkogQCWT97ePkThVoJGzrjZqNv_P2QHJOXbEvaTQB5kZzz9FzLtJCfQsFwk1kan9Iw");

            if (header.Value<string>("alg") == "RS256")
            {
                var x509Key = signingKeys[0] as X509SecurityKey;
                var rsaKey = signingKeys[0] as RsaSecurityKey;

                var rsa = x509Key != null ? x509Key.Certificate.GetRSAPublicKey() : rsaKey.Rsa;

                var verified = VerifyRS256($"{parts[0]}.{parts[1]}", signature, rsa);
                Console.WriteLine(verified);
                return verified;
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        static bool ValidateToken2(string id_token, params SecurityKey[] signingKeys)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(id_token))
            {
                throw new InvalidOperationException("No SecurityTokenHandler can authenticate this id_token!");
            }

            var parameters = new TokenValidationParameters();
            parameters.ValidAudience = "https://management.core.windows.net/";
            // this is just for Saml
            // paramaters.AudienceUriMode = AudienceUriMode.Always;
            parameters.ValidIssuer = "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/";
            parameters.ValidateIssuer = true;

            ////var tokens = new List<SecurityToken>();
            ////foreach (var key in config.IssuerKeys.Keys)
            ////{
            ////    tokens.AddRange(key.GetSecurityTokens());
            ////}
            ////parameters.IssuerSigningTokens = tokens;

            parameters.IssuerSigningKeys = signingKeys;

            //// validate
            //Claim servicePrincipal = null;
            SecurityToken validatedToken;
            var principal = handler.ValidateToken(id_token, parameters, out validatedToken);
            return true;

            //var puidClaims = GetPuidClaims();

            //if (!result.Claims.Any(c => puidClaims.Contains(c.Type)))
            //{
            //    // for ServicePrincipal jwt token, we will allow oid claim to represent user
            //    if (supportServicePrincipal)
            //    {
            //        servicePrincipal = result.Claims.FirstOrDefault(c => c.Type == ObjectIdClaimType);
            //        if (servicePrincipal == null)
            //        {
            //            throw new InvalidOperationException("The servicePrincipal claims does not contains oid type!");
            //        }
            //    }
            //    else
            //    {
            //        throw new InvalidOperationException(String.Format("The user {0} claims does not contains PUID type!", result.Identity.Name));
            //    }
            //}
        }

        static string GenerateJWT(RSA rsa)
        {
            //var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(GetByThumbprint("YOUR-CERT-THUMBPRINT-HERE"));
            //var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(new X509Certificate2(Convert.FromBase64String("MIIDBTCCAe2gAwIBAgIQbiJkXaenk61AKixVocnLRTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTAwNTAwMDAwMFoXDTI0MTAwNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2H9Y6Z+3BXUCtlbmXr6H5owYy15XTl3vdpOZLUkk4OV9LMsB1phjNp+wgl28eAgrNNfu4BTVlHdR9x6NTrSiIapsYjzzEz4mOmRh1Bw5tJxit0VEGn00/ZENniTjgeEFYgDHYwjrfZQ6dERBFiw1OQb2IG5f3KLtx92lUXeIZ7ZvTaPkUpc4Qd6wQZmWgzPqWFocRsJATGyZzXiiXQUrc9cVqm1bws3P0lFBcqNtv+AKDYKT5IRYLsyCkueQC9R6LUCsZVD7bVIkeQuA3iehJKIEAlk/e3j5E4VaCRs642ajb/z9kByTl2xL2k0AeZGc8/Rcy7SQn0LBcJNZGp/SMCAwEAAaMhMB8wHQYDVR0OBBYEFOLhl3BDPLNVYDe38Dp9JbUmd4kKMA0GCSqGSIb3DQEBCwUAA4IBAQAN4XwyqYfVdMl0xEbBMa/OzSfIbuI4pQWWpl3isKRAyhXezAX1t/0532LsIcYkwubLifnjHHqo4x1jnVqkvkFjcPZ12kjs/q5d1L0LxlQST/Uqwm/9/AeTzRZXtUKNBWBOWy9gmw9DEH593sNYytGAEerbWhCR3agUxsnQSYTTwg4K9cSqLWzHX5Kcz0NLCGwLx015/Jc7HwPJnp7q5Bo0O0VfhomDiEctIFfzqE5x9T9ZTUSWUDn3J7DYzs2L1pDrOQaNs/YEkXsKDP1j4tOFyxic6OvjQ10Yugjo5jg1uWoxeU8pI0BxY6sj2GZt3Ynzev2bZqmj68y0I9Z+NTZo")));

            var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);

            var mod = rsa.ExportParameters(includePrivateParameters: false).Modulus;
            // The "key ID" used for RSA key in GPG/PGP is the last 8 hex digits (4 bytes) of the modulus of the key.
            securityKey.KeyId = Base64UrlEncode(mod, mod.Length - 4, 4);

            var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, "RS256");

            var header = new JwtHeader(credentials);

            var payload = new JwtPayload
            {
                { "aud", "https://management.core.windows.net/"},
                { "iss", "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/"},
                { "exp", (Int32)(new DateTime(2019, 12, 9, 0, 0, 0, DateTimeKind.Utc).Subtract(new DateTime(1970, 1, 1))).TotalSeconds},
                { "iat", (Int32)(new DateTime(2019, 12, 7, 0, 0, 0, DateTimeKind.Utc).Subtract(new DateTime(1970, 1, 1))).TotalSeconds}
            };

            var token = new JwtSecurityToken(header, payload);

            var input = string.Join(".", new[] { token.EncodedHeader, token.EncodedPayload });
            var signature = SignRS256(input, rsa);
            return string.Join(".", new[] { input, Base64UrlEncoder.Encode(signature) });
        }

        //static JwtSecurityToken GenerateJWT(RSACryptoServiceProvider rsa, out string encoded)
        //{
        //    //var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(GetByThumbprint("YOUR-CERT-THUMBPRINT-HERE"));
        //    var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);

        //    var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, "RS256");

        //    var JWTHeader = new JwtHeader(credentials);

        //    var payload = new JwtPayload
        //    {
        //        { "iss", "Issuer-here"},
        //        { "exp", (Int32)(new DateTime(2019, 12, 9, 0, 0, 0, DateTimeKind.Utc).Subtract(new DateTime(1970, 1, 1))).TotalSeconds},
        //        { "iat", (Int32)(new DateTime(2019, 12, 7, 0, 0, 0, DateTimeKind.Utc).Subtract(new DateTime(1970, 1, 1))).TotalSeconds}
        //    };

        //    var token = new JwtSecurityToken(JWTHeader, payload);

        //    var input = string.Join(".", new[] { token.EncodedHeader, token.EncodedPayload });
        //    var signature = SignRS256(input, rsa);

        //    encoded = string.Join(".", new[] { input, Base64UrlEncoder.Encode(signature) });

        //    return token;
        //}

        //static byte[] Sign(string text, RSACryptoServiceProvider csp)
        //{
        //    // Hash the data
        //    var sha1 = new SHA1Managed();
        //    var encoding = new UnicodeEncoding();
        //    byte[] data = encoding.GetBytes(text);
        //    byte[] hash = sha1.ComputeHash(data);

        //    // Sign the hash
        //    return csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
        //}

        static byte[] SignRS256(string text, RSA rsa)
        {
            Encoding encoding = Encoding.UTF8;
            byte[] data = encoding.GetBytes(text);            

            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            //var sha256 = new SHA256CryptoServiceProvider();
            //byte[] hash = sha256.ComputeHash(data);
            //return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        static bool VerifyRS256(string text, byte[] signature, RSA rsa)
        {
            Encoding encoding = Encoding.UTF8;
            byte[] data = encoding.GetBytes(text);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            //var sha256 = new SHA256CryptoServiceProvider();
            //byte[] hash = sha256.ComputeHash(data);
            //return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        //static bool Verify(string text, byte[] signature, RSACryptoServiceProvider csp)
        //{
        //    // Hash the data
        //    SHA1Managed sha1 = new SHA1Managed();
        //    UnicodeEncoding encoding = new UnicodeEncoding();
        //    byte[] data = encoding.GetBytes(text);
        //    byte[] hash = sha1.ComputeHash(data);


        //    // Verify the signature with the hash
        //    return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);

        //}

    }
}
