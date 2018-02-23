
using Microsoft.AspNetCore.Authorization;
using PolicyServer.Client;
using System.Threading.Tasks;
using System.Linq;

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

			// here we can fetch user data, like current team
			// userService.get(id).currentTeam

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

			//managers have access only to his teams
			if (user.HasClaim(x => x.Type == "teams" && x.Value.Contains(requirement.TeamName)))
			{
				context.Succeed(requirement);
				return;
			}
		}
	}

}
