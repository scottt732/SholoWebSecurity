using System.Collections.Generic;
using System.Configuration.Provider;

namespace Sholo.Web.Security.Penalties
{
    public abstract class PenaltyRulesProviderBase : ProviderBase
    {
        public abstract void Initialize();
        public abstract IEnumerable<PenaltyRule> GetRules();
    }
}