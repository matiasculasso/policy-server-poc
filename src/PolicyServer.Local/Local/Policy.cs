// Copyright (c) Brock Allen, Dominick Baier, Michele Leroux Bustamante. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using PolicyServer.Client;

namespace PolicyServer.Local
{
    /// <summary>
    /// Models a policy
    /// </summary>
    public class Policy
    {
        /// <summary>
        /// Gets the roles.
        /// </summary>
        /// <value>
        /// The roles.
        /// </value>
        public List<Role> Roles { get; internal set; } = new List<Role>();

        /// <summary>
        /// Gets the permissions.
        /// </summary>
        /// <value>
        /// The permissions.
        /// </value>
        public List<Permission> Permissions { get; internal set; } = new List<Permission>();
        
        internal Task<PolicyResult> EvaluateAsync(ClaimsPrincipal user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

			var roles = Roles.Where(x=> x.Evaluate(user)).Select(x => x.Name);

			var userContext = user.Claims.FirstOrDefault(x => x.Type == "context");

			var permissions = Permissions
				.Where(x => x.Evaluate(roles) && userContext?.Value == x.Context)
				.Select(x => x.Name);

			var result = new PolicyResult()
            {
                Roles = roles.Distinct().ToArray(),
                Permissions = permissions.Distinct().ToArray()
            };

            return Task.FromResult(result);
        }
    }
}