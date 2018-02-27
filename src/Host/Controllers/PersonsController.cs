using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using PolicyServer.Client;
using Host.AspNetCoreCustomsPolicies;

namespace Host.Controllers
{
	public class PersonsController : Controller
	{
		private readonly IPolicyServerClient _client;
		private readonly IAuthorizationService _authz;

		public PersonsController(IPolicyServerClient client, IAuthorizationService authz)
		{
			_client = client;
			_authz = authz;
		}

		// [Authorize(Roles = "supervisor")]				
		// [Authorize(Policy = "persons.read.all")]
		// this is redundant, only for demo purposes 
		[Authorize(Policy = "persons.read.all", Roles = "supervisor")] 
		[Route("persons", Name = "personsGet")]
		public async Task<IActionResult> Get()
		{
			return View("success");
		}

		[Authorize(Policy = "persons.read.mine")]
		[Route("persons/{personId}", Name = "personsGetById")]
		public async Task<IActionResult> Get(string personId)
		{
			// checks if the requested user is the same than the logged user
			var currentUserRequirement = new CurrentUserRequirement { UserId = personId };
			var currentUserAllowed = await _authz.AuthorizeAsync(User, null, currentUserRequirement);

			if (currentUserAllowed.Succeeded)
			{
				return View("success");
			}

			// checks if the loggued user has the same location than the requested user.
			// here we could fetch the location  for the persionId and for logged user.
			var sameLocationRequirement = new SameLocationRequirement { Location = "desMoines" };
			var sameLocationAllowed = await _authz.AuthorizeAsync(User, null, sameLocationRequirement);

			if (sameLocationAllowed.Succeeded)
			{
				return View("success");
			}

			return Forbid();			
		}

		[Authorize(Policy="persons.write.mine")]
		[Route("persons/{personId}/edit", Name = "personsWrite")]
		public async Task<IActionResult> Write(string personId)
		{
			// check by role
			if (await _client.IsInRoleAsync(User, "supervisor"))
			{
				return View("success");
			}

			// checks if the requested user is the same than the logged user
			var currentUserRequirement = new CurrentUserRequirement { UserId = personId };
			var currentUserAllowed = await _authz.AuthorizeAsync(User, null, currentUserRequirement);

			if (currentUserAllowed.Succeeded)
			{
				return View("success");
			}

			var teamRequirement = new TeamMembersRequirement { TeamName = "teamOne" };
			var teamAllowed = await _authz.AuthorizeAsync(User, null, teamRequirement);

			if (!teamAllowed.Succeeded)
			{
				return Forbid();
			}			
			return View("success");
		}

		// this is equivalent to _client.HasPermissionAsync(User, "persons.delete");
		// [Authorize(Policy = "persons.delete")] 
		[Route("persons/{personId}/delete", Name = "personsDelete")]
		public async Task<IActionResult> Delte(string personId)
		{
			var canDeleteUser = await _client.HasPermissionAsync(User, "persons.delete");

			if (!canDeleteUser)
			{
				return Forbid();
			}

			return View("success");
		}
	}
}