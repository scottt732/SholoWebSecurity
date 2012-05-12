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
using System.Configuration;
using System.Web.Configuration;
using Sholo.Web.Security.Configuration;

namespace Sholo.Web.Security.Penalties.Provider
{
    public static class PenaltyRuleProviderManager
    {
        static PenaltyRuleProviderManager()
        {
            Initialize();
        }

        private static void Initialize()
        {
            var configuration = PenaltiesConfiguration.Penalties;

            if (configuration == null)
            {
                throw new ConfigurationErrorsException("Penalties configuration section is not set correctly.");
            }

            Providers = new PenaltyRuleProviderCollection();
            ProvidersHelper.InstantiateProviders(configuration.Providers, Providers, typeof(PenaltyRulesProviderBase));
            Providers.SetReadOnly();

            Provider = String.IsNullOrEmpty(configuration.DefaultProvider) ? new XmlPenaltyRulesProvider() : Providers[configuration.DefaultProvider];
            if (Provider == null)
            {
                throw new Exception("defaultProvider");
            }
            Provider.Initialize();
        }

        public static IEnumerable<PenaltyRule> GetAllRules()
        {
            foreach (PenaltyRulesProviderBase provider in Providers)
            {
                IEnumerable<PenaltyRule> rules = provider.GetRules();
                foreach (PenaltyRule rule in rules)
                {
                    yield return rule;
                }
            }
        }

        public static PenaltyRulesProviderBase Provider { get; private set; }

        public static PenaltyRuleProviderCollection Providers { get; private set; }
    }
}