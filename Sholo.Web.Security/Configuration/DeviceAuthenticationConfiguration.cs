﻿/*
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
    /// 
    /// </summary>
    public class DeviceAuthenticationConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "deviceAuthentication";

        public static DeviceAuthenticationConfiguration GetConfig()
        {
            return (DeviceAuthenticationConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName)
                ?? new DeviceAuthenticationConfiguration();
        }

        [ConfigurationProperty("providers")]
        public ProviderSettingsCollection Providers
        {
            get { return (ProviderSettingsCollection) base["providers"]; }
        }

        [ConfigurationProperty("stateProvider", DefaultValue="CacheDeviceAuthenticationTicketProvider")]
        public string StateProvider
        {
            get { return (string) base["stateProvider"]; }
            set { base["stateProvider"] = value; }
        }
    }
}