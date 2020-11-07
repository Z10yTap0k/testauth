using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace TestMvc
{
    public class ProxyAuthMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            if (context.Request.Cookies.TryGetValue("access_token", out var token) &&
                !context.Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                context.Request.Headers.Append(HeaderNames.Authorization, $"Bearer {token}");
            }

            await next(context);
        }
    }
}
