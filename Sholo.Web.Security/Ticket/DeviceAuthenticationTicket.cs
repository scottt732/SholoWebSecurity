using System;

namespace Sholo.Web.Security.Ticket
{
    /// <summary>
    /// 
    /// </summary>
    public class DeviceAuthenticationTicket : BaseAuthenticationTicket
    {
        /// <summary>
        /// The User-Agent of the device who initially received the
        /// DeviceAuthenticationTicket
        /// </summary>
        public string UserAgent { get; set; }

        /// <summary>
        /// The HostAddress of the device that initially received the
        /// DeviceAuthenticationTicket
        /// </summary>
        public string HostAddress { get; set; }
    }
}
