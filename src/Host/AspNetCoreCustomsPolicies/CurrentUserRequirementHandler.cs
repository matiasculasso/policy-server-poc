﻿
using Microsoft.AspNetCore.Authorization;
using PolicyServer.Client;
using System.Threading.Tasks;
using System.Linq;

namespace Host.AspNetCoreCustomsPolicies
{
	public class CurrentUserRequirementHandler : AuthorizationHandler<CurrentUserRequirement>
	{
		private readonly IPolicyServerClient _client;

		public CurrentUserRequirementHandler(IPolicyServerClient client)
		{
			_client = client;
		}

		protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, CurrentUserRequirement requirement)
		{
			var user = context.User;

			// supervisor has access to perform action over all users
			if (await _client.IsInRoleAsync(user, "supervisor"))
			{
				context.Succeed(requirement);
				return;
			}

			var userId = user.Claims.FirstOrDefault(x => x.Type == "sub").Value;
			// checks if the user is trying to access to his own data
			if (userId == requirement.UserId)
			{
				context.Succeed(requirement);
				return;
			}			
		}
	}
}
