/*
 * Copyright 2010-2012, Scott Holodak
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

using System.Configuration;

namespace Sholo.Web.Security.Configuration
{
    /// <summary>
    /// UserAuthenticationConfiguration ConfigurationSection for Web.config.
    /// </summary>
    public class UserAuthenticationConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "sholo.web/userAuthentication";

        /// <summary>
        /// The UserAuthenticationConfiguration configuration element defined 
        /// in web.config
        /// </summary>
        public static UserAuthenticationConfiguration GetConfig()
        {
            return (UserAuthenticationConfiguration) ConfigurationManager.GetSection(ConfigurationSectionName) 
                ?? new UserAuthenticationConfiguration();
        }

        [ConfigurationProperty("enabled", DefaultValue = "true", IsRequired = true)]
        public bool Enabled
        {
            get
            {
                bool result = true;
                if (this["enabled"] != null)
                {
                    bool.TryParse(this["enabled"].ToString(), out result);
                }
                return result;
            }
        }


        [ConfigurationProperty("enforceClientHostAddressValidation", DefaultValue = "true", IsRequired = false)]
        public bool EnforceClientHostAddressValidation
        {
            get
            {
                bool result = true;
                if (this["enforceClientHostAddressValidation"] != null)
                {
                    bool.TryParse(this["enforceClientHostAddressValidation"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("enforceUserAgentValidation", DefaultValue = "false", IsRequired = false)]
        public bool EnforceUserAgentValidation
        {
            get
            {
                bool result = true;
                if (this["enforceUserAgentValidation"] != null)
                {
                    bool.TryParse(this["enforceUserAgentValidation"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("hashSalt", DefaultValue = "S%OV6O7L7Dtuq@EEzS&Vfu9uWO&Wrn5DejYxakxcSeMW*JlS!X@hsfEJroei!L7@Z80LQ5^z8RbYRE1M@bwJGFnZSvikZtpvNVHcoDFl*$oY7%XNDBxvh6JbAIS93RI^j", IsRequired = false)]
        public string HashSalt
        {
            get
            {
                return this["hashSalt"] as string;
            }
        }

        [ConfigurationProperty("providers")]
        public ProviderSettingsCollection Providers
        {
            get { return (ProviderSettingsCollection)base["providers"]; }
        }

        [ConfigurationProperty("stateProvider", DefaultValue = "CacheUserAuthenticationTicketProvider")]
        public string StateProvider
        {
            get { return (string)base["stateProvider"]; }
            set { base["stateProvider"] = value; }
        }
    }
}