#pragma checksum "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "7be92ae46d17a2044663c80008ae25882359fdd2"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_About), @"mvc.1.0.view", @"/Views/Home/About.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Home/About.cshtml", typeof(AspNetCore.Views_Home_About))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\_ViewImports.cshtml"
using WebApp.Identity;

#line default
#line hidden
#line 2 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\_ViewImports.cshtml"
using WebApp.Identity.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"7be92ae46d17a2044663c80008ae25882359fdd2", @"/Views/Home/About.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"74a8383de03762724feed4c96ff772cb29145fc9", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_About : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 2 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml"
  
    ViewData["Title"] = "About";

#line default
#line hidden
            BeginContext(43, 46, true);
            WriteLiteral("\r\n    <h2>\r\n\r\n    </h2>\r\n\r\n    <ul>\r\n       \r\n");
            EndContext();
#line 12 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml"
             foreach(var claim in User.Claims)
            {

#line default
#line hidden
            BeginContext(152, 47, true);
            WriteLiteral("                <li> <b>\r\n                     ");
            EndContext();
            BeginContext(200, 10, false);
#line 15 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml"
                Write(claim.Type);

#line default
#line hidden
            EndContext();
            BeginContext(210, 53, true);
            WriteLiteral(" \r\n                     </b>: \r\n                     ");
            EndContext();
            BeginContext(264, 11, false);
#line 17 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml"
                Write(claim.Value);

#line default
#line hidden
            EndContext();
            BeginContext(275, 27, true);
            WriteLiteral("  \r\n                </li>\r\n");
            EndContext();
#line 19 "C:\Users\Diogo\dev\WebApp.Identity\WebApp.Identity\Views\Home\About.cshtml"
            }

#line default
#line hidden
            BeginContext(317, 22, true);
            WriteLiteral("       \r\n    </ul>\r\n\r\n");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
