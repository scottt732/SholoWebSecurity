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
    <multipleLogins> 
        <actions> 
            <clear /> 
            <add name="LogoffAllClients" logoff="None,AllSessions,ExistingSessions" refuseAuthenticatingUser="true|false" penaltyAction="warn|kick|ban" target="user,device" reason="" duration="" /> 
        </actions> 
        <rules> 
            <clear /> 
            <allow requires="SameUserAgent,SameHostAddress,SameDeviceFingerprint" except="SameUserAgent,SameHostAddress,SameDeviceFingerprint" /> 
            <forbid requires="SameUserAgent,SameHostAddress,SameDeviceFingerprint" except="SameUserAgent,SameHostAddress,SameDeviceFingerprint" onViolation="LogoffAllClients"  /> 
        </rules> 
    </multipleLogins>  
    */

    public class MultipleLoginsConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "multipleLogins";

        public static MultipleLoginsConfiguration GetConfig()
        {
            return (MultipleLoginsConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName)
                ?? new MultipleLoginsConfiguration();
        }

        [ConfigurationProperty("actions")]
        public ProviderSettingsCollection Actions
        {
            get
            {
                return (ProviderSettingsCollection)base["actions"];
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
