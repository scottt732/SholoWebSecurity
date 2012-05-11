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
      <requestProfiler enabled="true" updateCallbacksEnabled="true">
        <patterns>
          <clear />
          <add remoteSource="https://ourservice.com/patterns?allowCrawlers=1&allowPhpMyAdmin=1&refuseCountries={list of country codes}&refuseSpammers=1" updateDefinitionsAtStartup="true" updateDefinitionsEvery="0" updateCallback="~/Callback.ashx" />          
          <add remoteSource="https://intranet/patterns.xml" updateDefinitionsAtStartup="true" updateDefinitionsEvery="60" />
          <add localSource="~/App_Data/Patterns.xml" watchFile="true" />          
        </patterns>
      </requestProfiler>
    */

    public class RequestProfilerConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "requestProfiler";

        public static RequestProfilerConfiguration GetConfig()
        {
            return (RequestProfilerConfiguration)ConfigurationManager.GetSection(ConfigurationSectionName)
                ?? new RequestProfilerConfiguration();
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

        [ConfigurationProperty("updateCallbacksEnabled", DefaultValue = "false", IsRequired = false)]
        public bool UpdateCallbacksEnabled
        {
            get
            {
                bool result = true;
                if (this["updateCallbacksEnabled"] != null)
                {
                    bool.TryParse(this["updateCallbacksEnabled"].ToString(), out result);
                }
                return result;
            }
        }

        [ConfigurationProperty("patterns")]
        public ProviderSettingsCollection Patterns
        {
            get
            {
                return (ProviderSettingsCollection)base["patterns"];
            }
        }
    }
}
