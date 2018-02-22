using Microsoft.AspNetCore.Authorization;

namespace Host.AspNetCoreCustomsPolicies
{
	public class CurrentUserRequirement : IAuthorizationRequirement
	{
		public string UserId { get; set; }		
	}
}
