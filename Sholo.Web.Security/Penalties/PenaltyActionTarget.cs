using System;

namespace Sholo.Web.Security.Penalties
{
    [Flags]
    public enum PenaltyActionTarget
    {
        User = 1,
        IpAddress = 2,
        DeviceFingerprint = 4
    }
}