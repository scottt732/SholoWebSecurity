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
using System.ComponentModel;
using System.Configuration;
using Sholo.Web.Security.Penalties;

namespace Sholo.Web.Security.Configuration
{
    public class PenaltyRuleElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsRequired = true)]
        public string Name
        {
            get { return (string)this["name"]; }
            set { this["name"] = value; }
        }

        [ConfigurationProperty("points", IsRequired = false)]
        public int Points
        {
            get { return (int)this["points"]; }
            set { this["points"] = value; }
        }


        [ConfigurationProperty("pointsSince", IsRequired = false)]
        public int PointsSince
        {
            get { return (int)this["pointsSince"]; }
            set { this["pointsSince"] = value; }
        }


        [ConfigurationProperty("suspiciousRequestsCount", IsRequired = false)]
        public int SuspiciousRequestsCount
        {
            get { return (int)this["suspiciousRequestsCount"]; }
            set { this["suspiciousRequestsCount"] = value; }
        }


        [ConfigurationProperty("suspiciousRequestsSince", IsRequired = false)]
        public int SuspiciousRequestsSince
        {
            get { return (int)this["suspiciousRequestsSince"]; }
            set { this["suspiciousRequestsSince"] = value; }
        }

        [ConfigurationProperty("maliciousRequestsCount", IsRequired = false)]
        public int MaliciousRequestsCount
        {
            get { return (int)this["maliciousRequestsCount"]; }
            set { this["maliciousRequestsCount"] = value; }
        }


        [ConfigurationProperty("maliciousRequestsSince", IsRequired = false)]
        public int MaliciousRequestsSince
        {
            get { return (int)this["maliciousRequestsSince"]; }
            set { this["maliciousRequestsSince"] = value; }
        }

        [ConfigurationProperty("exceptionsCount", IsRequired = false)]
        public int ExceptionsCount
        {
            get { return (int)this["exceptionsCount"]; }
            set { this["exceptionsCount"] = value; }
        }


        [ConfigurationProperty("exceptionsSince", IsRequired = false)]
        public int ExceptionsSince
        {
            get { return (int)this["exceptionsSince"]; }
            set { this["exceptionsSince"] = value; }
        }

        [ConfigurationProperty("exceptionType", IsRequired = false)]
        [TypeConverter(typeof(TypeNameConverter))]
        public Type ExceptionType
        {
            get { return (Type)this["exceptionType"]; }
            set { this["exceptionType"] = value; }
        }

        [ConfigurationProperty("warningsCount", IsRequired = false)]
        public int WarningsCount
        {
            get { return (int)this["warningsCount"]; }
            set { this["warningsCount"] = value; }
        }

        [ConfigurationProperty("warningsSince", IsRequired = false)]
        public int WarningsSince
        {
            get { return (int)this["warningsSince"]; }
            set { this["warningsSince"] = value; }
        }

        [ConfigurationProperty("kicksCount", IsRequired = false)]
        public int KicksCount
        {
            get { return (int)this["kicksCount"]; }
            set { this["kicksCount"] = value; }
        }

        [ConfigurationProperty("kicksSince", IsRequired = false)]
        public int KicksSince
        {
            get { return (int)this["kicksSince"]; }
            set { this["kicksSince"] = value; }
        }

        [ConfigurationProperty("bansCount", IsRequired = false)]
        public int BansCount
        {
            get { return (int)this["bansCount"]; }
            set { this["bansCount"] = value; }
        }

        [ConfigurationProperty("bansSince", IsRequired = false)]
        public int BansSince
        {
            get { return (int)this["bansSince"]; }
            set { this["bansSince"] = value; }
        }

        [ConfigurationProperty("action", IsRequired = true)]
        public PenaltyAction Action
        {
            get { return (PenaltyAction)this["action"]; }
            set { this["action"] = value; }
        }

        [ConfigurationProperty("actionTarget", IsRequired = true)]
        public PenaltyActionTarget ActionTarget
        {
            get { return (PenaltyActionTarget)this["actionTarget"]; }
            set { this["actionTarget"] = value; }
        }

        [ConfigurationProperty("actionDuration", IsRequired = true)]
        public int ActionDuration
        {
            get { return (int)this["actionDuration"]; }
            set { this["actionDuration"] = value; }
        }

        [ConfigurationProperty("incrementPoints", IsRequired = false)]
        public int IncrementPoints
        {
            get { return (int)this["incrementPoints"]; }
            set { this["incrementPoints"] = value; }
        }

        [ConfigurationProperty("responseDelay", IsRequired = false)]
        public int ResponseDelay
        {
            get { return (int)this["responseDelay"]; }
            set { this["responseDelay"] = value; }
        }

        [ConfigurationProperty("reason", IsRequired = false)]
        public string Reason
        {
            get { return (string)this["reason"]; }
            set { this["reason"] = value; }
        }

    }
}