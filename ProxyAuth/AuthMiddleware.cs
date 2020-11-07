using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;

namespace ProxyAuth
{
    public class AuthMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var certificate2Collection = store.Certificates.Find(X509FindType.FindByIssuerName, "localhost", false);

            var certificate = certificate2Collection[0];


            if (!AcceptJson(context.Request.Headers) || !TryGetReturnUrl(context.Request.Query, out var returnUrl))
            {
                await next(context);
                return;
            }

            var identity = GetIdentity();

            var now = DateTime.UtcNow;
            var jwt = new JwtSecurityToken(
                issuer: "proxyauth",
                audience: "test",
                notBefore: now,
                claims: identity.Claims,
                expires: now.Add(TimeSpan.FromMinutes(30)),
                signingCredentials: new X509SigningCredentials(certificate)
            );
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            if (!string.IsNullOrEmpty(returnUrl))
            {
                context.Response.Cookies.Append("access_token", encodedJwt, new CookieOptions
                {
                    HttpOnly = true
                });
                context.Response.Redirect(returnUrl);
                return;
            }

            var response = JsonConvert.SerializeObject(new { access_token = encodedJwt });
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/json";
            context.Response.ContentLength = response.Length;
            await context.Response.WriteAsync(response);
        }

        private static bool TryGetReturnUrl(IQueryCollection query, out string returnUrl)
        {
            if (!query.TryGetValue("return_url", out var returnUrls))
            {
                returnUrl = null;
                return false;
            }

            returnUrl = returnUrls.FirstOrDefault();
            return !string.IsNullOrEmpty(returnUrl);
        }

        private static bool AcceptJson(IHeaderDictionary headers)
        {
            return headers.TryGetValue(HeaderNames.Accept, out var values) && values.Any(x => x == "application/json");
        }

        private ClaimsIdentity GetIdentity()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, "testapi"),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, "role")
            };
            var claimsIdentity =
                new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
            return claimsIdentity;
        }
    }
}
