using System;
using System.Collections.Generic;
using Sholo.Web.Security.Configuration;

namespace Sholo.Web.Security.Penalties
{
    public class XmlPenaltyRulesProvider : PenaltyRulesProviderBase
    {
        private List<PenaltyRule> _rules;

        public XmlPenaltyRulesProvider()
        {

        }

        public override void Initialize()
        {
            var penaltiesConfiguration = PenaltiesConfiguration.Penalties;
            _rules = new List<PenaltyRule>();
            foreach (PenaltyRuleElement rulesElement in penaltiesConfiguration.Rules)
            {
                PenaltyRule rule = null;
                if (rulesElement.Points != 0)
                {
                    rule = new PenaltyRule(RuleType.Points, rulesElement.PointsSince);
                }
                else if (rulesElement.SuspiciousRequestsCount != 0)
                {
                    rule = new PenaltyRule(RuleType.SuspiciousRequest, rulesElement.SuspiciousRequestsSince);
                }
                else if (rulesElement.MaliciousRequestsCount != 0)
                {
                    rule = new PenaltyRule(RuleType.MaliciousRequest, rulesElement.MaliciousRequestsSince);
                }
                else if (rulesElement.ExceptionsCount != 0)
                {
                    rule = new PenaltyRule(RuleType.Exception, rulesElement.ExceptionsSince);
                    rule.ExceptionType = rulesElement.ExceptionType;
                }
                else if (rulesElement.WarningsCount != 0)
                {
                    rule = new PenaltyRule(RuleType.Warning, rulesElement.WarningsSince);
                }
                else if (rulesElement.KicksCount != 0)
                {
                    rule = new PenaltyRule(RuleType.Kick, rulesElement.KicksSince);
                }
                else if (rulesElement.BansCount != 0)
                {
                    rule = new PenaltyRule(RuleType.Ban, rulesElement.BansSince);
                }
                else
                {
                    throw new InvalidOperationException("Invalid Rule");
                }

                rule.Action = rulesElement.Action;
                rule.ActionDuration = rulesElement.ActionDuration;
                rule.ActionTarget = rulesElement.ActionTarget;
                rule.IncrementPoints = rulesElement.IncrementPoints;
                rule.Reason = rulesElement.Reason;
                rule.ResponseDelay = rulesElement.ResponseDelay;
                _rules.Add(rule);
            }
        }

        public override IEnumerable<PenaltyRule> GetRules()
        {
            if (_rules == null)
            {
                Initialize();
            }

            return _rules;
        }
    }
}