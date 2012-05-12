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

using System;
using System.Collections.Generic;
using Sholo.Web.Security.Configuration;

namespace Sholo.Web.Security.Penalties.Provider
{
    public class XmlPenaltyRulesProvider : PenaltyRulesProviderBase
    {
        private List<PenaltyRule> _rules;

        public XmlPenaltyRulesProvider()
        {

        }

        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            base.Initialize(name, config);

            var penaltiesConfiguration = PenaltiesConfiguration.GetConfig();
            _rules = new List<PenaltyRule>();
            foreach (PenaltyRuleElement rulesElement in penaltiesConfiguration.Rules)
            {
                PenaltyRule rule = null;
                if (rulesElement.Points != 0)
                {
                    rule = new PenaltyRule(TriggerType.Points, rulesElement.PointsSince);
                }
                else if (rulesElement.SuspiciousRequestsCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.SuspiciousRequest, rulesElement.SuspiciousRequestsSince);
                }
                else if (rulesElement.MaliciousRequestsCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.MaliciousRequest, rulesElement.MaliciousRequestsSince);
                }
                else if (rulesElement.ExceptionsCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.Exception, rulesElement.ExceptionsSince);
                    rule.ExceptionType = rulesElement.ExceptionType;
                }
                else if (rulesElement.WarningsCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.Warning, rulesElement.WarningsSince);
                }
                else if (rulesElement.KicksCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.Kick, rulesElement.KicksSince);
                }
                else if (rulesElement.BansCount != 0)
                {
                    rule = new PenaltyRule(TriggerType.Ban, rulesElement.BansSince);
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
            return _rules;
        }
    }
}