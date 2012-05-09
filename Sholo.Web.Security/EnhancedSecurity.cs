/*
 * Copyright 2010-2012, Scott Holodak
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
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Security;
using Sholo.Web.Security.Configuration;

namespace Sholo.Web.Security
{
    /// <summary>
    /// EnhancedSecurity exposes a public API for use in working with 
    /// Stateful Forms Authentication in the .NET framework.  It also exposes the 
    /// configured configuration parameters as public static properties.
    /// </summary>
    public sealed class EnhancedSecurity
    {
        #region Fields
        // Thread-safe initialization
        private static readonly object LockObject;
        private static bool _initialized;

        internal static SecurityProfilerConfiguration SecurityProfilerConfig;

        private static int _minimumDelayOnSuspiciousRequest;
        private static int _maximumDelayOnSuspiciousRequest;
        private static int _minimumDelayOnMaliciousRequest;
        private static int _maximumDelayOnMaliciousRequest;
        private static int _minimumDelayOnCryptographicException;
        private static int _maximumDelayOnCryptographicException;
        #endregion

        #region Methods
        /// <summary>
        /// Static constructor
        /// </summary>
        static EnhancedSecurity()
        {
            LockObject = new object();
        }

        /// <summary>
        /// Initializes configuration-related properties and validates configuration.
        /// </summary>        
        public static void Initialize()
        {
            if (!_initialized)
            {
                lock (LockObject)
                {
                    if (!_initialized)
                    {
                        FormsAuthentication.Initialize();
                        SecurityProfilerConfig = SecurityProfilerConfiguration.GetConfig();

                        // _maintainServerTicketStore = UserAuthenticationConfig.StateProvider

                        _minimumDelayOnSuspiciousRequest = SecurityProfilerConfig.MinimumDelayOnSuspiciousRequest;
                        _maximumDelayOnSuspiciousRequest = SecurityProfilerConfig.MaximumDelayOnSuspiciousRequest;
                        _minimumDelayOnMaliciousRequest = SecurityProfilerConfig.MinimumDelayOnMaliciousRequest;
                        _maximumDelayOnMaliciousRequest = SecurityProfilerConfig.MaximumDelayOnMaliciousRequest;
                        _minimumDelayOnCryptographicException = SecurityProfilerConfig.MinimumDelayOnCryptographicException;
                        _maximumDelayOnCryptographicException = SecurityProfilerConfig.MaximumDelayOnCryptographicException;

                        _initialized = true;
                    }
                }
            }
        }

        ///<summary>
        /// Delay the execution of the suspicious request by a random amount of time between 
        /// MinimumDelayOnSuspiciousRequest and MaximumDelayOnSuspiciousRequest
        ///</summary>
        public static void DelaySuspiciousResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnSuspiciousRequest, MaximumDelayOnSuspiciousRequest));
        }

        ///<summary>
        /// Delay the execution of the malicious request by a random amount of time between 
        /// MinimumDelayOnMaliciousRequest and MaximumDelayOnMaliciousRequest
        ///</summary>
        public static void DelayMaliciousResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnMaliciousRequest, MaximumDelayOnMaliciousRequest));
        }

        ///<summary>
        /// Delay the execution of a request that caused a CryptographicException by a 
        /// random amount of time between MinimumDelayOnCryptographicException and 
        /// MaximumDelayOnCryptographicException
        ///</summary>
        public static void DelayCryptographicExceptionResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnCryptographicException, MaximumDelayOnCryptographicException));                
        }
        #endregion

        #region Internal Methods
        internal static FormsAuthenticationStatus GetFormsAuthStatus()
        {
            if (HttpContext.Current.Items["TicketStatus"] != null && !string.IsNullOrEmpty(HttpContext.Current.Items["TicketStatus"].ToString()))
            {
                try
                {
                    return (FormsAuthenticationStatus)Enum.Parse(typeof(FormsAuthenticationStatus), HttpContext.Current.Items["TicketStatus"].ToString());
                }
                catch
                {
                    return FormsAuthenticationStatus.Invalid;
                }
            }
            return FormsAuthenticationStatus.NotFound;
        }

        internal static void SetFormsAuthStatus(FormsAuthenticationStatus status)
        {
            switch (status)
            {
                case FormsAuthenticationStatus.Valid:
                case FormsAuthenticationStatus.NotFound:
                    HttpContext.Current.Items["TicketStatus"] = status.ToString();
                    break;
                default:
                    HttpContext.Current.Items["TicketStatus"] = FormsAuthenticationStatus.Invalid.ToString();
                    UserAuthentication.ClearAuthCookie();
                    break;
            }
        }
        #endregion

        #region Properties
        /// <summary>
        /// The minimum number of milliseconds to delay on receipt of a suspicious request
        /// </summary>
        public static int MinimumDelayOnSuspiciousRequest
        {
            get
            {
                Initialize();
                return _minimumDelayOnSuspiciousRequest;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on receipt of a suspicious request
        /// </summary>
        public static int MaximumDelayOnSuspiciousRequest
        {
            get
            {
                Initialize();
                return _maximumDelayOnSuspiciousRequest;
            }
        }

        /// <summary>
        /// The minimum number of milliseconds to delay on receipt of a malicious request
        /// </summary>
        public static int MinimumDelayOnMaliciousRequest
        {
            get
            {
                Initialize();
                return _minimumDelayOnMaliciousRequest;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on receipt of a malicious request
        /// </summary>
        public static int MaximumDelayOnMaliciousRequest
        {
            get
            {
                Initialize();
                return _maximumDelayOnMaliciousRequest;
            }
        }

        /// <summary>
        /// The minimum number of milliseconds to delay on production of a CryptographicException
        /// </summary>
        public static int MinimumDelayOnCryptographicException
        {
            get
            {
                Initialize();
                return _minimumDelayOnCryptographicException;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on production of a CryptographicException
        /// </summary>
        public static int MaximumDelayOnCryptographicException
        {
            get
            {
                Initialize();
                return _maximumDelayOnCryptographicException;
            }
        }
        #endregion
    }
}