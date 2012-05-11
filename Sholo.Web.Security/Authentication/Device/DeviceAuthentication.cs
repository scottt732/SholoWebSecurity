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
using System.Web.Configuration;
using Sholo.Web.Security.Authentication.Device.Provider;
using Sholo.Web.Security.Configuration;

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

        private static DeviceAuthenticationTicketProviderBase _provider;
        private static DeviceAuthenticationTicketProviderCollection _providers;

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
                        DeviceAuthenticationConfiguration configuration = (DeviceAuthenticationConfiguration) ConfigurationManager.GetSection("DeviceAuthentication");

                        if (configuration == null)
                            throw new ConfigurationErrorsException("DeviceAuthentication configuration section is not configured correctly.");

                        _providers = new DeviceAuthenticationTicketProviderCollection();
                        ProvidersHelper.InstantiateProviders(configuration.Providers, _providers, typeof (DeviceAuthenticationTicketProviderCollection));
                        _providers.SetReadOnly();

                        _provider = _providers[configuration.StateProvider];

                        if (_provider == null)
                            throw new Exception("defaultProvider");
                    }
                }
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
    }
}
