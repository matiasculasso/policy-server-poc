
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

		protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, 
			TeamMembersRequirement requirement)
		{			
			var user = context.User;

			// supervisor has access to perform action over all records
			if (await _client.IsInRoleAsync(user, "supervisor"))
			{
				context.Succeed(requirement);
				return;
			}

			// we can also pass the permission as a parameter
			if (await _client.HasPermissionAsync(user, "persons.read.team") == false)
			{
				return;
			}

			// here we can fetch the team for the logged user consumming a service
			// for demo purposes we are fetching the team from user claims
			var team = user.Claims.FirstOrDefault(x => x.Type == "teams")?.Value;

			if (team == requirement.TeamName)
			{
				context.Succeed(requirement);
				return;
			}
		}
	}

}
