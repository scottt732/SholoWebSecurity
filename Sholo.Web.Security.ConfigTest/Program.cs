using System;
using Sholo.Web.Security.Authentication.User;

namespace Sholo.Web.Security.ConfigTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(UserAuthentication.Enabled);
            Console.ReadLine();
        }
    }
}
