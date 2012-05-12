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
using System.Configuration;
using System.Security.Cryptography;
using System.Web.Configuration;
using System.Web.Security;
using Sholo.Web.Security.Authentication.Device.Provider;
using Sholo.Web.Security.Configuration;

/*
<deviceAuthentication enforceClientHostAddressValidation="true" enforceUserAgentValidation="false" hashSalt="evenSaltier" stateProvider="CacheDeviceAuthenticationTicketProvider">
    <providers>
        <clear />
        <add name="CacheDeviceAuthenticationTicketProvider" type="Sholo.Web.Security.Authentication.Device.Provider.CacheDeviceAuthenticationTicketProvider, Sholo.Web.Security" />
    </providers>
</deviceAuthentication>
 */
namespace Sholo.Web.Security.Authentication.Device
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class DeviceAuthentication
    {
        // Thread-safe initialization
        private static readonly object LockObject;
        private static bool _initialized;

        // System.Web/Authentication and System.Web/Authentication/Forms static classes
        internal static DeviceAuthenticationConfiguration DeviceAuthenticationConfig;

        private static bool _enabled;
        private static DeviceAuthenticationTicketProviderBase _provider;
        private static DeviceAuthenticationTicketProviderCollection _providers;
        private static bool _enforceClientHostAddressValidation;
        private static bool _enforceUserAgentValidation;
        private static string _hashSalt;
        private static SHA512Managed _hashAlgorithm;
        private static string _path;
        private static bool _requireSsl;
        private static bool _slidingExpiration;

        static DeviceAuthentication()
        {
            LockObject = new object();
        }

        private static void Initialize()
        {
            if (!_initialized)
            {
                lock (LockObject)
                {
                    if (!_initialized)
                    {
                        FormsAuthentication.Initialize();
                        DeviceAuthenticationConfig = DeviceAuthenticationConfiguration.GetConfig();

                        if (DeviceAuthenticationConfig != null)
                        {
                            _enabled = true;
                            _hashAlgorithm = new SHA512Managed();
                            _enforceClientHostAddressValidation = DeviceAuthenticationConfig.EnforceClientHostAddressValidation;
                            _enforceUserAgentValidation = DeviceAuthenticationConfig.EnforceUserAgentValidation;
                            _hashSalt = DeviceAuthenticationConfig.HashSalt;
                            _path = DeviceAuthenticationConfig.Path;
                            _requireSsl = DeviceAuthenticationConfig.RequireSsl;
                            _slidingExpiration = DeviceAuthenticationConfig.SlidingExpiration;

                            _providers = new DeviceAuthenticationTicketProviderCollection();
                            ProvidersHelper.InstantiateProviders(DeviceAuthenticationConfig.Providers, _providers, typeof (DeviceAuthenticationTicketProviderBase));
                            _providers.SetReadOnly();

                            _provider = _providers[DeviceAuthenticationConfig.StateProvider];

                            if (_provider == null)
                            {
                                throw new Exception("defaultProvider");
                            }

                            if (_hashSalt == "ExampleSalt")
                            {
                                throw new ConfigurationErrorsException("For security purposes, you must change the example salt in web.config's userAuthentication element.`");
                            }
                        }
                        else
                        {
                            _enabled = false;
                        }

                        _initialized = true;
                    }
                }
            }
        }

        public static bool Enabled
        {
            get
            {
                Initialize();
                return _enabled;
            }
        }

        public static bool EnforceClientHostAddressValidation
        {
            get
            {
                Initialize();
                return _enforceClientHostAddressValidation;
            }
        }

        public static bool EnforceUserAgentValidation
        {
            get
            {
                Initialize();
                return _enforceUserAgentValidation;
            }
        }

        public static string HashSalt
        {
            get
            {
                Initialize();
                return _hashSalt;
            }
        }

        public static DeviceAuthenticationTicketProviderBase Provider
        {
            get
            {
                Initialize();
                return _provider;
            }
        }

        public static DeviceAuthenticationTicketProviderCollection Providers
        {
            get
            {
                Initialize();
                return _providers;
            }
        }

        public static SHA512Managed HashAlgorithm
        {
            get
            {
                Initialize();
                return _hashAlgorithm;
            }
        }

        public static string Path
        {
            get
            {
                Initialize();
                return _path;
            }
        }

        public static bool RequireSsl
        {
            get
            {
                Initialize();
                return _requireSsl;
            }
        }

        public static bool SlidingExpiration
        {
            get
            {
                Initialize();
                return _slidingExpiration;
            }
        }
    }
}
