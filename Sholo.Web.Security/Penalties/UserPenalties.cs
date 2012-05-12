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

using System.Collections.Generic;
using System.Web.Configuration;
using Sholo.Web.Security.Configuration;
using Sholo.Web.Security.Penalties.Provider;

namespace Sholo.Web.Security.Penalties
{
    public static class UserPenalties
    {
        #region Fields
        // Thread-safe initialization
        private static readonly object LockObject;
        private static bool _initialized;
        
        private static bool _enabled;
        private static List<PenaltyRule> _allRules;
        private static PenaltyRuleProviderCollection _providers;
        #endregion

        static UserPenalties()
        {
            LockObject = new object();
        }

        private static void Initialize()
        {
            if (!_initialized)
            {
                lock (LockObject)
                {
                    if (!_initialized)
                    {
                        var configuration = PenaltiesConfiguration.Penalties;

                        if (configuration != null)
                        {
                            _enabled = true;

                            _providers = new PenaltyRuleProviderCollection();
                            ProvidersHelper.InstantiateProviders(configuration.Providers, Providers, typeof (PenaltyRulesProviderBase));

                            if (Providers.Count == 0)
                            {
                                XmlPenaltyRulesProvider xmlProvider = new XmlPenaltyRulesProvider();
                                _providers.Add(xmlProvider);
                                xmlProvider.Initialize();
                            }
                            Providers.SetReadOnly();

                            _allRules = new List<PenaltyRule>();
                            foreach (PenaltyRulesProviderBase provider in Providers)
                            {
                                IEnumerable<PenaltyRule> rules = provider.GetRules();
                                foreach (PenaltyRule rule in rules)
                                {
                                    _allRules.Add(rule);
                                }
                            }
                        } 
                        else
                        {
                            _enabled = false;                            
                        }

                        _initialized = true;
                    }
                }
            }
        }

        public static bool Enabled
        {
            get
            {
                Initialize();
                return _enabled;
            }
        }

        public static IEnumerable<PenaltyRule> GetAllRules()
        {
            Initialize();
            return _allRules;
        }

        public static PenaltyRuleProviderCollection Providers 
        { 
            get
            {
                Initialize();
                return _providers;
            }
        }
    }
}