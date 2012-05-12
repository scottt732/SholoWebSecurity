/*
 * Copyright 2010-2012, Scott Holodak, Alex Friedman
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using Sholo.Web.Security.Authentication.User;
using Sholo.Web.Security.Penalties;
using Sholo.Web.Security.Penalties.Provider;

namespace Sholo.Web.Security.ConfigTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("UserAuthentication: {0}", UserAuthentication.Enabled);
            if (UserAuthentication.Enabled)
            {
                Console.WriteLine("EnforceClientHostAddressValidation: {0}", UserAuthentication.EnforceClientHostAddressValidation);
                Console.WriteLine("EnforceUserAgentValidation: {0}", UserAuthentication.EnforceUserAgentValidation);
                Console.WriteLine("FormsTimeout: {0}", UserAuthentication.FormsTimeout);
                Console.WriteLine("HashAlgorithm: {0}", UserAuthentication.HashAlgorithm);
                Console.WriteLine("HashSalt: {0}", UserAuthentication.HashSalt);
                Console.WriteLine("StateProvider: {0}", UserAuthentication.StateProvider);
                Console.WriteLine("Provider: {0}", UserAuthentication.Provider.GetType().FullName);
                Console.WriteLine();
            }

            Console.WriteLine("User Penalties: {0}", UserPenalties.Enabled);
            if (UserPenalties.Enabled)
            {
                List<PenaltyRule> list = new List<PenaltyRule>(UserPenalties.GetAllRules());
                Console.WriteLine(list.Count);
            }

            string line;
            while (FetchCommand(out line))
            {
                DispatchCommand(line);
            }
        }

        private static bool FetchCommand(out string line)
        {
            Console.Write("> ");
            line = Console.ReadLine();
            return !string.IsNullOrEmpty(line) && line.IndexOf("exit", StringComparison.InvariantCultureIgnoreCase) < 0;
        }

        private static void DispatchCommand(string line)
        {
        }
    }
}
