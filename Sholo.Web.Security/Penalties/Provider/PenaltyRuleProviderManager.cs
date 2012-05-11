using System;
using System.Configuration;
using System.Web.Configuration;
using Sholo.Web.Security.Configuration;

namespace Sholo.Web.Security.Penalties
{
    public static class PenaltyRuleProviderManager
    {
        static PenaltyRuleProviderManager()
        {
            Initialize();
        }

        private static void Initialize()
        {
            var configuration = PenaltiesConfiguration.Penalties;

            if (configuration == null)
            {
                throw new ConfigurationErrorsException("Penalties configuration section is not set correctly.");
            }

            Providers = new PenaltyRuleProviderCollection();
            ProvidersHelper.InstantiateProviders(configuration.Providers, Providers, typeof(PenaltyRulesProviderBase));
            Providers.SetReadOnly();

            Provider = String.IsNullOrEmpty(configuration.DefaultProvider) ? new XmlPenaltyRulesProvider() : Providers[configuration.DefaultProvider];
            if (Provider == null)
            {
                throw new Exception("defaultProvider");
            }
            Provider.Initialize();
        }

        public static PenaltyRulesProviderBase Provider { get; private set; }

        public static PenaltyRuleProviderCollection Providers { get; private set; }
    }
}