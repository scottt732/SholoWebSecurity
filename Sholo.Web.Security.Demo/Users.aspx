<%@ Page Title="Users Page" Language="C#" MasterPageFile="Demo.master" CodeFile="Users.aspx.cs" Inherits="Users" %>
<%@ Register TagPrefix="Sholo" TagName="CookieMonster" Src="~/Controls/CookieMonster.ascx" %>
<asp:Content runat="server" ID="Body" ContentPlaceHolderID="Body">    
    <sholo:CookieMonster runat="Server" />
</asp:Content>