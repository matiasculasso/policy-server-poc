
using Microsoft.AspNetCore.Authorization;
using PolicyServer.Client;
using System.Threading.Tasks;

namespace Host.AspNetCoreCustomsPolicies
{
	public class SameLocationRequirementHandler : AuthorizationHandler<SameLocationRequirement>
	{
		private readonly IPolicyServerClient _client;

		public SameLocationRequirementHandler(IPolicyServerClient client)
		{
			_client = client;
		}

		protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, SameLocationRequirement requirement)
		{
			var user = context.User;

			// supervisor has access to perform action over all records
			if (await _client.IsInRoleAsync(user, "supervisor"))
			{
				context.Succeed(requirement);
				return;
			}

			//only managers are allowed
			if (await _client.IsInRoleAsync(user, "manager") == false)
			{
				return;
			}


			if (user.HasClaim(x => x.Type == "location" && x.Value.Contains(requirement.Location)))
			{
				context.Succeed(requirement);
				return;
			}
		}
	}

}
