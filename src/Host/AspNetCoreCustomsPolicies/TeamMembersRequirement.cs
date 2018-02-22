using Microsoft.AspNetCore.Authorization;

namespace Host.AspNetCoreCustomsPolicies
{
	public class TeamMembersRequirement : IAuthorizationRequirement
	{
		public string TeamName { get; set; }
	}
}
