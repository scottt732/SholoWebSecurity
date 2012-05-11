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
    /*
    <responseDelays enabled="true"> 
        <rules>
            <clear />        
            <add type="SuspiciousRequest"      minimumDelay="1500"  maximumDelay="5000" /> 
            <add type="MaliciousRequest"       minimumDelay="1500"  maximumDelay="5000" /> 
            <add type="Exception"              minimumDelay="15000" maximumDelay="50000" exceptionType="System.Security.Cryptography.CryptographicException" /> 
        </rules>
    </responseDelays>     
    */
    public class ResponseDelaysConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "responseDelays";

        public static ResponseDelaysConfiguration GetConfig()
        {
            return (ResponseDelaysConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName)
                ?? new ResponseDelaysConfiguration();
        }

        [ConfigurationProperty("enabled", DefaultValue = "true", IsRequired = false)]
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

        [ConfigurationProperty("rules")]
        public ProviderSettingsCollection Rules
        {
            get
            {
                return (ProviderSettingsCollection)base["rules"];
            }
        }
    }
}
