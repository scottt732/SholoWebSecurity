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
    /// StatefulFormsAuthenticationConfiguration ConfigurationSection for Web.config.
    /// </summary>
    public class StatefulFormsAuthenticationConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "statefulFormsAuthentication";

        /// <summary>
        /// The StatefulFormsAuthenticationConfiguration configuration element defined 
        /// in web.config
        /// </summary>
        public static StatefulFormsAuthenticationConfiguration GetConfig()
        {
            return (StatefulFormsAuthenticationConfiguration) ConfigurationManager.GetSection(ConfigurationSectionName) 
                ?? new StatefulFormsAuthenticationConfiguration();
        }

        /// <summary>
        /// The ticket store to use to store tickets created by the server 
        /// for enhanced validation and revocation support in subsequent requests.
        /// <remarks>
        /// Currently supported values: CacheUserAuthenticationTicketStore
        /// </remarks>
        /// </summary>
        [ConfigurationProperty("ticketStore", DefaultValue = "CacheUserAuthenticationTicketStore", IsRequired = false)]
        public string TicketStore
        {
            get
            {
                return this["ticketStore"] as string;
            }
        }

        [ConfigurationProperty("enforceClientHostAddressValidation", DefaultValue = "true", IsRequired = false)]
        public bool EnforceClientHostAddressValidation {
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

        [ConfigurationProperty("maintainServerTicketStore", DefaultValue = "true", IsRequired = false)]
        public bool MaintainServerTicketStore
        {
            get
            {
                bool result = true;
                if (this["maintainServerTicketStore"] != null)
                {
                    bool.TryParse(this["maintainServerTicketStore"].ToString(), out result);
                }
                return result;
            }            
        }

        [ConfigurationProperty("minimumDelayOnSuspiciousRequest", DefaultValue = "1500", IsRequired = false)]
        public int MinimumDelayOnSuspiciousRequest
        {
            get
            {
                int result = 1500;
                if (this["minimumDelayOnSuspiciousRequest"] != null)
                {
                    int.TryParse(this["minimumDelayOnSuspiciousRequest"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("maximumDelayOnSuspiciousRequest", DefaultValue = "5000", IsRequired = false)]
        public int MaximumDelayOnSuspiciousRequest
        {
            get
            {
                int result = 5000;
                if (this["maximumDelayOnSuspiciousRequest"] != null)
                {
                    int.TryParse(this["maximumDelayOnSuspiciousRequest"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("minimumDelayOnMaliciousRequest", DefaultValue = "1500", IsRequired = false)]
        public int MinimumDelayOnMaliciousRequest
        {
            get
            {
                int result = 1500;
                if (this["minimumDelayOnMaliciousRequest"] != null)
                {
                    int.TryParse(this["minimumDelayOnMaliciousRequest"].ToString(), out result);
                }
                return result;
            }            
        }

        [ConfigurationProperty("maximumDelayOnMaliciousRequest", DefaultValue = "5000", IsRequired = false)]
        public int MaximumDelayOnMaliciousRequest
        {
            get
            {
                int result = 5000;
                if (this["maximumDelayOnMaliciousRequest"] != null)
                {
                    int.TryParse(this["maximumDelayOnMaliciousRequest"].ToString(), out result);
                }
                return result;
            }            
        }

        [ConfigurationProperty("minimumDelayOnCryptographicException", DefaultValue = "15000", IsRequired = false)]
        public int MinimumDelayOnCryptographicException
        {
            get
            {
                int result = 500;
                if (this["minimumDelayOnCryptographicException"] != null)
                {
                    int.TryParse(this["minimumDelayOnCryptographicException"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("maximumDelayOnCryptographicException", DefaultValue = "30000", IsRequired = false)]
        public int MaximumDelayOnCryptographicException
        {
            get
            {
                int result = 750;
                if (this["maximumDelayOnCryptographicException"] != null)
                {
                    int.TryParse(this["maximumDelayOnCryptographicException"].ToString(), out result);
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
    }
}