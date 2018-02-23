// Copyright (c) Brock Allen, Dominick Baier, Michele Leroux Bustamante. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Host.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string userName, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!string.IsNullOrWhiteSpace(userName))
            {
                var claims = new List<Claim>();

                if (userName == "mati")
                {
                    claims = new List<Claim>
                    {
                        new Claim("sub", "1"),
                        new Claim("name", "Matias"),
						new Claim("teams", "['teamOne']"),
						new Claim("location", "desMoines"),
						new Claim("tenant","I07"),
						new Claim("client","enspire"),
						// new Claim("context","persons"),
					};
                }
                else if (userName == "seba")
                {
                    claims = new List<Claim>
                    {
                        new Claim("sub", "2"),
                        new Claim("name", "Sebastian"),
						new Claim("teams", "['teamOne']"),
						new Claim("location", "desMoines"),
						new Claim("tenant","I07"),
						new Claim("client","enspire"),
						// new Claim("context","persons"),
					};
                }
				else if (userName == "andres")
				{
					claims = new List<Claim>
					{
						new Claim("sub", "3"),
						new Claim("name", "Andres"),
						new Claim("teams", "['teamOne']"),
						new Claim("location", "desMoines"),
						new Claim("tenant","I07"),
						new Claim("client","enspire"),
						// new Claim("context","persons"),
					};
				}
				else
                {
                    claims = new List<Claim>
                    {
                        new Claim("sub", "99"),
                        new Claim("name", userName),
                    };
                }

                var id = new ClaimsIdentity(claims, "password", "name", "role");
                var p = new ClaimsPrincipal(id);

                await HttpContext.SignInAsync(p);
                return LocalRedirect(returnUrl);
            }

            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return Redirect("/");
        }

        public IActionResult AccessDenied() => View();
    }
}