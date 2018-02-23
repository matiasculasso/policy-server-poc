using Microsoft.AspNetCore.Http;
using PolicyServer.Client;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace PolicyServer.AspNetCore
{
    public class RequestPathTransformationToContextMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestPathTransformationToContextMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next.</param>
        public RequestPathTransformationToContextMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        /// <summary>
        /// Invoke
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="client">The client.</param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context, IPolicyServerClient client)
        {
            if (context.User.Identity.IsAuthenticated)
            {                
                var appContext = context.Request.Path.Value.Split('/')[1].ToLower();

                var identity = context.User.Identities
						.Where(x => x.AuthenticationType == "PolicyServerMiddleware")
						.FirstOrDefault();              
                
                if (identity.HasClaim(x => x.Type == "context"))
                    identity.RemoveClaim(identity.FindFirst("context"));

                identity.AddClaim(new Claim("context", appContext));
            }

            await _next(context);
        }

    }
}
