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
    /*
    <penalties enabled="true"> 
        <rules> 
            <clear /> 
            <add name=""
                suspiciousRequestsCount="#"      suspiciousRequestsSince=""
                maliciousRequestsCount="#"       maliciousRequestsSince=""
                cryptographicExceptionsCount="#" cryptographicExceptionsSince=""
                warningsCount="#"                warningsSince=""
                kicksCount="#"                   kicksSince=""
                bansCount="#"                    bansSince=""
                action="Warn|Kick|Ban"
                duration=""
                reason="" /> 
        </rules> 
    </penalties> 
    */

    public class PenaltiesConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "penalties";

        public static PenaltiesConfiguration GetConfig()
        {
            return (PenaltiesConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName)
                ?? new PenaltiesConfiguration();
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
