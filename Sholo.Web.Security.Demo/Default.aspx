<%@ Page Title="Public Page" MasterPageFile="~/Demo.master" Language="C#" AutoEventWireup="true"  CodeFile="Default.aspx.cs" Inherits="_Default" %>
<%@ Register TagPrefix="Sholo" TagName="CookieMonster" Src="~/Controls/CookieMonster.ascx" %>
<%--
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
--%>
<asp:Content runat="server" ID="Body" ContentPlaceHolderID="Body">    
    <sholo:CookieMonster ID="CookieMonster1" runat="Server" />
</asp:Content>