using System;

namespace Sholo.Web.Security.Penalties
{
    public class PenaltyRule
    {
        public PenaltyRule(RuleType ruleType, int durationSince)
        {
            DurationSince = durationSince;
            RuleType = ruleType;
        }

        public string Name { get; set; }
        public RuleType RuleType { get; private set; }
        public int DurationSince { get; private set; }
        public PenaltyAction Action { get; set; }
        public PenaltyActionTarget ActionTarget { get; set; }
        public int ActionDuration { get; set; }
        public int IncrementPoints { get; set; }
        public int ResponseDelay { get; set; }
        public string Reason { get; set; }
        public Type ExceptionType { get; set; }
    }
}