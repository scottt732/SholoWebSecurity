using System.Configuration;
using Sholo.Web.Security.Penalties;

namespace Sholo.Web.Security.Configuration
{
    public class PenaltiesConfiguration : ConfigurationSection
    {
        private static PenaltiesConfiguration _penalties
            = ConfigurationManager.GetSection("sholo.web/penalties") as PenaltiesConfiguration;

        public static PenaltiesConfiguration Penalties
        {
            get
            {
                return _penalties;
            }
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
            get { return this["providers"] as ProviderSettingsCollection; }
        }

        [ConfigurationProperty("rules", IsDefaultCollection = false),
     ConfigurationCollection(typeof(PenaltyRulesCollection), AddItemName = "add", ClearItemsName = "clear", RemoveItemName = "remove")]
        public PenaltyRulesCollection Rules
        {
            get { return this["rules"] as PenaltyRulesCollection; }
        }
    }
}
