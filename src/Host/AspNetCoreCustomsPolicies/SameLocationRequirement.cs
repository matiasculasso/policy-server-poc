using Microsoft.AspNetCore.Authorization;

namespace Host.AspNetCoreCustomsPolicies
{
	public class SameLocationRequirement : IAuthorizationRequirement
	{
		public string Location { get; set; }
	}
}
