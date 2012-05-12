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
    public class PenaltiesConfiguration : ConfigurationSection
    {
        private const string ConfigurationSectionName = "sholo.web/penalties";

        public static PenaltiesConfiguration GetConfig()
        {
            return (PenaltiesConfiguration) ConfigurationManager.GetSection(ConfigurationSectionName);
        }

        [ConfigurationProperty("enabled", IsRequired = false)]
        public bool Enabled
        {
            get { return (bool)this["enabled"]; }
            set { this["enbled"] = value; }
        }

        [ConfigurationProperty("defaultProvider")]
        public string DefaultProvider
        {
            get
            {
                return (string)base["defaultProvider"];
            }
            set
            {
                base["defaultProvider"] = value;
            }
        }

        [ConfigurationProperty("providers")]
        public ProviderSettingsCollection Providers
        {
            get
            {
                return this["providers"] as ProviderSettingsCollection;
            }
        }

        [ConfigurationProperty("rules", IsDefaultCollection = false), ConfigurationCollection(typeof(PenaltyRulesCollection), AddItemName = "add", ClearItemsName = "clear", RemoveItemName = "remove")]
        public PenaltyRulesCollection Rules
        {
            get
            {
                return this["rules"] as PenaltyRulesCollection;
            }
        }
    }
}
