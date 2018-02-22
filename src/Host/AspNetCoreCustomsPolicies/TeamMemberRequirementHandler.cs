
using Microsoft.AspNetCore.Authorization;
using PolicyServer.Client;
using System.Threading.Tasks;

namespace Host.AspNetCoreCustomsPolicies
{
	public class TeamMemberRequirementHandler : AuthorizationHandler<TeamMembersRequirement>
	{
		private readonly IPolicyServerClient _client;

		public TeamMemberRequirementHandler(IPolicyServerClient client)
		{
			_client = client;
		}

		protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TeamMembersRequirement requirement)
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

			if (user.HasClaim(x => x.Type == "team" && x.Value.Contains(requirement.TeamName)))
			{
				context.Succeed(requirement);
				return;
			}
		}
	}

}
