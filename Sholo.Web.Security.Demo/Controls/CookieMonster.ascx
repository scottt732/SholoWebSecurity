<%@ Control Language="C#" AutoEventWireup="true" CodeFile="CookieMonster.ascx.cs" Inherits="User_controls_CookieMonster" %>
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <td valign="middle">
            <asp:Label ID="StatusMessage" runat="server" />
        </td>
        <td width="22" valign="top">
            <asp:Panel ID="StatusColor" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
</table>
<br />
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <th colspan="2">
            Current Request
        </th>
        <th width="22">
            <asp:Panel ID="CurrentRequestValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </th>
    </tr>
    <tr>
        <td width="225">
            Host Address
        </td>
        <td>
            <asp:Label ID="RequestHostAddress" runat="server" />
        </td>
        <td width="22">
            <asp:Panel ID="RequestHostAddressValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td width="225">
            IsAuthenticated
        </td>
        <td>
            <asp:Checkbox ID="RequestIsAuthenticated" runat="server" />
        </td>
        <td>
            <asp:Panel ID="RequestIsAuthenticatedValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td width="225">
            User Name
        </td>
        <td>
            <asp:Label ID="RequestUserName" runat="server" />
        </td>
        <td>
            <asp:Panel ID="RequestUserNameValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
</table>
<br />
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <th colspan="2">
            Forms Authentication Cookie
        </th>
        <th width="22">
            <asp:Panel ID="FormsAuthenticationCookieValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </th>
    </tr>
    <tr>
        <td width="225">
            Domain
        </td>
        <td>
            <asp:Label ID="CookieDomain" runat="server" />
        </td>
        <td width="22">
            <asp:Panel ID="CookieDomainValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Expires
        </td>
        <td>
            <asp:TextBox ID="CookieExpires" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="CookieExpiresValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Name
        </td>
        <td>
            <asp:Label ID="CookieName" runat="server" />
        </td>
        <td>
            <asp:Panel ID="CookieNameValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Path
        </td>
        <td>
            <asp:TextBox ID="CookiePath" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="CookiePathValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Secure
        </td>
        <td>
            <asp:CheckBox ID="CookieSecure" runat="server" />
        </td>
        <td>
            <asp:Panel ID="CookieSecureValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td valign="top">
            Client Value
        </td>
        <td>
            <code><asp:Label ID="CookieValueClient" runat="server" /></code>
        </td>
        <td valign="top">
            <asp:Panel ID="CookieValueClientValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td valign="top">
            Server Value (Substituted)
        </td>
        <td>
            <code><asp:Label ID="CookieValueServer" runat="server" /></code>
        </td>
        <td valign="top">
            <asp:Panel ID="CookieValueServerValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
</table>
<br />
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <th colspan="2">
            Forms Authentication Ticket
        </th>
        <th width="22">
            <asp:Panel ID="FormsAuthenticationTicketValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </th>
    </tr>
    <tr>
        <td width="225">
             Cookie Path
        </td>
        <td>
            <asp:TextBox ID="TicketCookiePath" runat="server" Width="98%" />
        </td>
        <td width="22">
            <asp:Panel ID="TicketCookiePathValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Expiration
        </td>
        <td>
            <asp:TextBox ID="TicketExpiration" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketExpirationValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Is Persistent
        </td>
        <td>
            <asp:CheckBox ID="TicketIsPersistent" runat="server" />
        </td>
        <td>
            <asp:Panel ID="TicketIsPersistentValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Issue Date
        </td>
        <td>
            <asp:TextBox ID="TicketIssueDate" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketIssueDateValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Name
        </td>
        <td>
            <asp:TextBox ID="TicketName" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketNameValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Client User Data
        </td>
        <td>
            <asp:TextBox ID="TicketUserDataClient" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketUserDataClientValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Server User Data (Substituted)
        </td>
        <td>
            <asp:TextBox ID="TicketUserDataServer" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketUserDataServerValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
             Version
        </td>
        <td>
            <asp:Label ID="TicketVersion" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="TicketVersionValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
</table>
<br />
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <th colspan="2">
            Server Authentication Ticket
        </th>
        <th width="22">
            <asp:Panel ID="ServerAuthenticationTicketValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </th>
    </tr>
    <tr>
        <td>
            Key
        </td>
        <td>
            <asp:TextBox ID="ServerKey" runat="server" Width="98%" />
        </td>
        <td width="22">
            <asp:Panel ID="ServerKeyValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td width="225">
            Username
        </td>
        <td>
            <asp:TextBox ID="ServerUsername" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerUsernameValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td width="225">
            Host Address
        </td>
        <td>
            <asp:TextBox ID="ServerHostAddress" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerHostAddressValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Cookie Name
        </td>
        <td>
            <asp:TextBox ID="ServerCookieName" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerCookieNameValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Cookie Domain
        </td>
        <td>
            <asp:TextBox ID="ServerCookieDomain" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerCookieDomainValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Cookie Path
        </td>
        <td>
            <asp:TextBox ID="ServerCookiePath" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerCookiePathValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Cookie Secure
        </td>
        <td>
            <asp:CheckBox ID="ServerCookieSecure" runat="server" />
        </td>
        <td>
            <asp:Panel ID="ServerCookieSecureValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Ticket Expiration
        </td>
        <td>
            <asp:TextBox ID="ServerTicketExpiration" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketExpirationValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Ticket Is Persistent
        </td>
        <td>
            <asp:CheckBox ID="ServerTicketIsPersistent" runat="server" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketIsPersistentValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Ticket Issue Date
        </td>
        <td>
            <asp:TextBox ID="ServerTicketIssueDate" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketIssueDateValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td valign="top"> 
            Ticket User Data
        </td>
        <td>
            <asp:TextBox ID="ServerTicketUserData" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketUserDataValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Ticket Version
        </td>
        <td>
            <asp:TextBox ID="ServerTicketVersion" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketVersionValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
    <tr>
        <td>
            Ticket Hash
        </td>
        <td>
            <asp:TextBox ID="ServerTicketHash" runat="server" Width="98%" />
        </td>
        <td>
            <asp:Panel ID="ServerTicketHashValid" runat="server" BackColor="Gainsboro" BorderStyle="Solid" BorderWidth="1" style="font-size: 1px; height: 20px; width: 20px;">&nbsp;</asp:Panel>
        </td>
    </tr>
</table>
<br />
<table class="block" cellpadding="2" cellspacing="0" border="1" width="100%" style="border-collapse: collapse;">
    <tr>
        <th colspan="2">
            Write Changes to...
        </th>
    </tr>
    <tr>
        <td width="225">
            FormsAuthenticationCookie
        </td>
        <td>
            <asp:Checkbox ID="TamperFormsAuthenticationCookie" runat="server" />
        </td>
    </tr>
    <tr>
        <td width="225">
            FormsAuthenticationTicket
        </td>
        <td>
            <asp:Checkbox ID="TamperFormsAuthenticationTicket" runat="server" />
            (implicitly changes FormsAuthenticationCookie's Value)
        </td>
    </tr>
    <tr>
        <td width="225">
            UserAuthenticationTicket
        </td>
        <td>
            <asp:Checkbox ID="TamperServerAuthenticationTicket" runat="server" />
        </td>
    </tr>
    <tr>
        <td width="225">
            &nbsp;
        </td>
        <td>
            <asp:Button ID="TamperButton" runat="server" OnClick="TamperButton_Click" Text="Tamper" />
        </td>
    </tr>
</table>
