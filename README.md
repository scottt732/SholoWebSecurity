sholo.web.security
==================

sholo.web.security provides a set of HttpModules and static classes for 
enhancing web application security.  The library is compatible with 
ASP.NET 2.0 and later and provides various security features on top of 
the existing FormsAuthentication subsystem built into .NET.

### Features

- Stateful Forms Authentication
  - Revoke outstanding tickets (kick users)
  - Enhanced ticket validation & verification
  - Restrict tickets by IP address or User-Agent to prevent cookie hijacking attacks
- Device Authentication
  - Require persistent device authentication cookies to access protected resources
  - Provides an additional level of user identify verification
- More coming soon

### Contributors

* Scott Holodak
* Alex Friedman

### Links

* Source Code: https://github.com/scottt732/SholoWebSecurity

### License ###

    Copyright 2010-2012, Scott Holodak, Alex Friedman

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.