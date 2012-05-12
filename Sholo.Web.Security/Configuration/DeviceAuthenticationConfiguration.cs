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

using System.Configuration;

namespace Sholo.Web.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public class DeviceAuthenticationConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "sholo.web/deviceAuthentication";

        public static DeviceAuthenticationConfiguration GetConfig()
        {
            return (DeviceAuthenticationConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName);
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

        [ConfigurationProperty("hashSalt", DefaultValue = "ExampleSalt", IsRequired = true)]
        public string HashSalt
        {
            get
            {
                return this["hashSalt"] as string;
            }
        }

        [ConfigurationProperty("cookieName", DefaultValue = "DEVICE_AUTH", IsRequired = false)]
        public string CookieName
        {
            get
            {
                return this["cookieName"] as string;
            }
        }

        [ConfigurationProperty("deviceAuthenticateUrl", IsRequired = true)]
        public string DeviceAuthenticateUrl
        { 
            get
            {
                return this["deviceAuthenticateUrl"] as string;            
            }
        }

        // TODO: See what the Forms DefaultValue is
        [ConfigurationProperty("path", DefaultValue = "", IsRequired = false)]
        public string Path
        {
            get
            {
                return this["path"] as string;
            }
        }

        [ConfigurationProperty("requireSSL", DefaultValue = "false", IsRequired = false)]
        public bool RequireSsl
        {
            get
            {
                bool result = false;
                if (this["requireSSL"] != null)
                {
                    bool.TryParse(this["requireSSL"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("slidingExpiration", DefaultValue = "true", IsRequired = false)]
        public bool SlidingExpiration
        {
            get
            {
                bool result = true;
                if (this["slidingExpiration"] != null)
                {
                    bool.TryParse(this["slidingExpiration"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("providers")]
        public ProviderSettingsCollection Providers
        {
            get
            {
                return (ProviderSettingsCollection) base["providers"];
            }
        }

        [ConfigurationProperty("stateProvider", DefaultValue = "CacheDeviceAuthenticationTicketProvider")]
        public string StateProvider
        {
            get
            {
                return this["stateProvider"] as string;
            }
        }
    }
}
