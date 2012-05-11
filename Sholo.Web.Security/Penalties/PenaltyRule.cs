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

namespace Sholo.Web.Security.Penalties
{
    public class PenaltyRule
    {
        public PenaltyRule(TriggerType triggerType, int durationSince)
        {
            DurationSince = durationSince;
            TriggerType = triggerType;
        }

        public string Name { get; set; }
        public TriggerType TriggerType { get; private set; }
        public int DurationSince { get; private set; }
        public PenaltyAction Action { get; set; }
        public PenaltyActionTarget ActionTarget { get; set; }
        public int ActionDuration { get; set; }
        public int IncrementPoints { get; set; }
        public int ResponseDelay { get; set; }
        public string Reason { get; set; }
        public Type ExceptionType { get; set; }
        
        /*
        points="10"                       pointsSince="10"
        suspiciousRequestsCount="10"      suspiciousRequestsSince="10"
        maliciousRequestsCount="10"       maliciousRequestsSince="10"
        exceptionsCount="10"              exceptionsSince="10"
        exceptionType="System.Exception"
        warningsCount="10"                warningsSince="10"
        kicksCount="10"                   kicksSince="10"
        bansCount="10"                    bansSince="10"
        action="Warn"
        actionTarget="User,IpAddress"
        actionDuration="10"
        incrementPoints="10"
        responseDelay="10"
        reason="No reason"
         */
    }
}