<%@ Page Title="Public Page" MasterPageFile="~/Demo.master" Language="C#" AutoEventWireup="true"  CodeFile="Default.aspx.cs" Inherits="_Default" %>
<%@ Register TagPrefix="Sholo" TagName="CookieMonster" Src="~/Controls/CookieMonster.ascx" %>
<asp:Content runat="server" ID="Body" ContentPlaceHolderID="Body">    
    <sholo:CookieMonster ID="CookieMonster1" runat="Server" />
</asp:Content>