using System.Configuration.Provider;

namespace Sholo.Web.Security.Penalties
{
    public class PenaltyRuleProviderCollection : ProviderCollection
    {
        public new PenaltyRulesProviderBase this[string name]
        {
            get { return (PenaltyRulesProviderBase)base[name]; }
        }
    }
}