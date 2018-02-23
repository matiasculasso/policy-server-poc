﻿using Microsoft.AspNetCore.Mvc;
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
		// [Authorize(Policy = "persons.getAll")]
		// [Authorize(Policy = "persons.getAll", Roles = ["supervisor"])]
		[Route("persons", Name = "personsGet")]
		public async Task<IActionResult> Get()
		{
			var result = await _client.EvaluateAsync(User);
			return View("success");
		}

		[Authorize(Policy = "persons.getById")]
		[Route("persons/{personId}", Name = "personsGetById")]
		public async Task<IActionResult> Get(string personId)
		{			
			// check current user can get our own data
			var currentUserRequirement = new CurrentUserRequirement { UserId = personId };
			var currentUserAllowed = await _authz.AuthorizeAsync(User, null, currentUserRequirement);

			if (currentUserAllowed.Succeeded)
			{
				return View("success");
			}

			// if the loggued user has the same location than the requested user
			// here we could fetch the location  for the persionId and for logged user

			var sameLocationRequirement = new SameLocationRequirement { Location = "desMoines" };
			var sameLocationAllowed = await _authz.AuthorizeAsync(User, null, sameLocationRequirement);

			if (sameLocationAllowed.Succeeded)
			{
				return View("success");
			}

			return Forbid();			
		}

		[Authorize(Policy="persons.write")]
		[Route("persons/{personId}/edit", Name = "personsWrite")]
		public async Task<IActionResult> Write(string personId)
		{
			// checking by role
			if (await _client.IsInRoleAsync(User, "supervisor"))
			{
				return View("success");
			}

			var teamRequirement = new TeamMembersRequirement { TeamName = "teamOne" };
			// var teamRequirement = new TeamMembersRequirement { TeamName = "teamTwo" };
			var teamAllowed = await _authz.AuthorizeAsync(User, null, teamRequirement);

			if (!teamAllowed.Succeeded)
			{
				return Forbid();
			}			
			return View("success");
		}

		[Authorize(Policy = "persons.delete")]
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