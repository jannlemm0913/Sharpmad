using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Cryptography;
using System.Collections.Specialized;
using System.Net.Sockets;
using System.IdentityModel.Tokens;

namespace Sharpmad
{
    internal class DNS
    {
        public static void InvokeDnsUpdate(
            string domainController = null,
            string realm = null,
            string username = null,
            string password = null,
            string hash = null,
            string zone = null,
            int dnsTtl = 600,
            int? dnsPreference = null,
            int? dnsPriority = null,
            int? dnsWeight = null,
            int? dnsPort = null,
            string security = "Secure",
            string dnsType = "A",
            string dnsName = null,
            string dnsData = null,
            bool recordCheck = false,
            bool tcpClientAuth = false)
        {
            if (tcpClientAuth && String.IsNullOrEmpty(password) && String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[-] TCPClientAuth requires a username and password");
                return;
            }

            switch (dnsType)
            {
                case "MX":
                    {
                        if (dnsPreference == null)
                        {
                            Console.WriteLine("[-] MX records require a DNSPreference");
                            return;
                        }
                        break;
                    }

                case "PTR":
                    {
                        if (zone == null)
                        {
                            Console.WriteLine("[-] PTR records require a DNSZone");
                            return;
                        }
                        break;
                    }

                case "SRV":
                    {
                        if (dnsPriority == null && dnsWeight == null && dnsPort == null && dnsData != null)
                        {
                            Console.WriteLine("[-] DNSType SRV requires DNSPriority, DNSWeight, and DNSPort");
                            return;
                        }

                        if (!dnsName.Contains("._tcp.") && !dnsName.Contains("._udp."))
                        {
                            Console.WriteLine("[-] DNSName doesn't contain a protocol (\"._tcp.\" or \"._udp.\")");
                            return;
                        }
                        break;
                    }
            }

            if (security.ToLower() != "nonsecure" && !String.IsNullOrEmpty(username) && String.IsNullOrEmpty(hash) && String.IsNullOrEmpty(password))
            {
                Console.WriteLine("[-] This security requires a username and password or hash");
                return;
            }

            if (String.IsNullOrEmpty(domainController) || String.IsNullOrEmpty(realm) || String.IsNullOrEmpty(zone))
            {
                try
                {
                    Domain currentDomain = Domain.GetCurrentDomain();

                    if (string.IsNullOrEmpty(domainController))
                    {
                        domainController = currentDomain.PdcRoleOwner.Name;
                        Console.WriteLine($"[+] Domain Controller = {domainController}");
                        Console.WriteLine($"[+] Domain = {currentDomain.Name}");
                    }

                    if (string.IsNullOrEmpty(realm))
                    {
                        realm = currentDomain.Name;
                        Console.WriteLine($"[+] Kerberos Realm = {realm}");
                    }

                    if (string.IsNullOrEmpty(zone))
                    {
                        zone = currentDomain.Name;
                        Console.WriteLine($"[+] DNS Zone = {zone}");
                    }

                    zone = zone.ToLower();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] {ex.Message}");
                    return;
                }
            }

            bool kerberosTcpClient = false;
            string salt = "";

            if (tcpClientAuth || !String.IsNullOrEmpty(hash) || (tcpClientAuth && !String.IsNullOrEmpty(username) && !String.IsNullOrEmpty(password)))
            {
                kerberosTcpClient = true;
                realm = realm.ToUpper();

                if (username.Contains("\\"))
                {
                    username = username.Substring(username.IndexOf("\\") + 1);
                }

                if (username.Contains("@"))
                {
                    username = username.Substring(0, username.IndexOf("@"));
                }

                if (username.EndsWith("$"))
                {
                    salt = realm + "host" + username.Substring(0, username.Length - 1) + "." + realm.ToLower();
                }
                else
                {
                    salt = realm + username;
                }

                Console.WriteLine($"[+] Salt = {salt}");
            }

            if (String.IsNullOrEmpty(username))
            {
                username = System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            }

            bool dnsRecordExists = false;
            string dnsUpdateResponseStatus = "";
            byte[] dnsClientReceive = new byte[2048];

            if (recordCheck)
            {
                string queryName;

                if (dnsType.ToUpper() != "MX" && !dnsName.Contains("."))
                {
                    queryName = dnsName + "." + zone;
                }
                else
                {
                    queryName = dnsName;
                }

                using (System.Net.Sockets.TcpClient dnsClient = new System.Net.Sockets.TcpClient())
                {
                    dnsClient.Client.ReceiveTimeout = 3000;

                    try
                    {
                        dnsClient.Connect(domainController, 53);
                        using (var dnsClientStream = dnsClient.GetStream())
                        {
                            OrderedDictionary packetDnsQuery = NewPacketDNSQuery(queryName, dnsType);
                            byte[] dnsClientSend = ConvertFromPacketOrderedDictionary(packetDnsQuery);
                            dnsClientStream.Write(dnsClientSend, 0, dnsClientSend.Length);
                            dnsClientStream.Flush();
                            dnsClientStream.Read(dnsClientReceive, 0, dnsClientReceive.Length);

                            if (dnsClientReceive[9] != 0)
                            {
                                dnsRecordExists = true;
                                Console.WriteLine($"[-] A record of type {dnsType} already exists for {dnsName}");
                                return;
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine($"[-] {domainController} did not respond on TCP port 53");
                    }
                }
            }

            if (!recordCheck || (recordCheck && !dnsRecordExists))
            {
                TcpClient dnsClient = new TcpClient();
                dnsClient.Client.ReceiveTimeout = 3000;

                if (security.ToLower() != "secure")
                {
                    try
                    {
                        dnsClient.Connect(domainController, 53);
                    }
                    catch
                    {
                        Console.WriteLine($"{domainController} did not respond on TCP port 53");
                    }

                    if (dnsClient.Connected)
                    {
                        NetworkStream dnsClientStream = dnsClient.GetStream();
                        byte[] transactionId = NewRandomByteArray(2);
                        OrderedDictionary packetDnsUpdate = NewPacketDNSUpdate(transactionId, zone, dnsName, dnsType, dnsTtl, dnsPreference, dnsPriority, dnsWeight, dnsPort, dnsData);
                        byte[] dnsUpdate = ConvertFromPacketOrderedDictionary(packetDnsUpdate);
                        byte[] dnsClientSend = dnsUpdate;
                        dnsClientStream.Write(dnsClientSend, 0, dnsClientSend.Length);
                        dnsClientStream.Flush();
                        dnsClientStream.Read(dnsClientReceive, 0, dnsClientReceive.Length);
                        dnsUpdateResponseStatus = GetDNSUpdateResponseStatus(dnsClientReceive);
                        Console.WriteLine($"[+] DNS Update response: {dnsUpdateResponseStatus}");
                        dnsClient.Close();
                        dnsClientStream.Close();
                    }
                }
            }

            byte[] baseKey = null;
            byte[] domainControllerBytes = Encoding.UTF8.GetBytes(domainController);
            byte[] kerberosUsernameBytes = Encoding.UTF8.GetBytes(username);
            byte[] kerberosRealmBytes = Encoding.UTF8.GetBytes(realm);
            byte[] tkeyName = null;

            if (security.ToLower() == "secure" || (security.ToLower() == "auto" && dnsUpdateResponseStatus == "0xA805"))
            {
                Random random = new Random();
                string tkey = "6" + random.Next(10, 99) + "-ms-7.1-" + random.Next(1000, 9999) + "." + random.Next(10000000, 99999999) +
                    "-" + random.Next(1000, 9999) + "-11e7-" + random.Next(1000, 9999) + "-000c296694e0";
                tkey = tkey.Replace(" ", "");
                Console.WriteLine("[+] TKEY name: " + tkey);
                tkeyName = Encoding.UTF8.GetBytes(tkey);
                tkeyName = new byte[] { 0x08 }.Concat(tkeyName).Concat(new byte[] { 0x00 }).ToArray();
                tkeyName[9] = 0x06;
                tkeyName[16] = 0x24;

                bool krbConnected = false;
                TcpClient kerberosClient = new TcpClient();
                bool authKrbSuccess = false;
                byte[] asrepKey = null;
                string asrepPayload = "";
                byte[] kerberosClientReceive = null;


                if (kerberosTcpClient)
                {
                    kerberosClient.Client.ReceiveTimeout = 3000;

                    try
                    {
                        kerberosClient.Connect(domainController, 88);
                        krbConnected = true;
                    }
                    catch
                    {
                        Console.WriteLine($"{domainController} did not respond on TCP port 88");
                    }
                }

                if (!kerberosTcpClient || krbConnected)
                {
                    if (kerberosTcpClient)
                    {
                        if (!String.IsNullOrEmpty(hash))
                        {
                            //base_key = Enumerable.Range(0, hash.Length / 2).Select(i => (char)Convert.ToInt16(hash.Substring(i * 2, 2), 16)).ToArray(); ????
                            Console.WriteLine("[!] Hash authentication not yet implemented! Exiting.");
                            return;
                        }
                        else
                        {
                            baseKey = GetKerberosAES256BaseKey(salt, password);
                        }

                        byte[] ke_key = GetKerberosAES256UsageKey("encrypt", 1, baseKey);
                        byte[] ki_key = GetKerberosAES256UsageKey("integrity", 1, baseKey);
                        byte[] nonce = NewRandomByteArray(4);
                        NetworkStream kerberosClientStream = kerberosClient.GetStream();
                        kerberosClientReceive = new byte[2048];
                        OrderedDictionary packetASReq = NewPacketKerberosASREQ(kerberosUsernameBytes, kerberosRealmBytes, domainControllerBytes, nonce);
                        byte[] AS_REQ = ConvertFromPacketOrderedDictionary(packetASReq);

                        byte[] kerberosClientSend = AS_REQ;
                        kerberosClientStream.Write(kerberosClientSend, 0, kerberosClientSend.Length);
                        kerberosClientStream.Flush();
                        kerberosClientStream.Read(kerberosClientReceive, 0, kerberosClientReceive.Length);
                        byte[] PAC_Timestamp = NewKerberosPACTimestamp(ke_key);
                        byte[] PAC_ENC_Timestamp = ProtectKerberosAES256CTS(ke_key, PAC_Timestamp);
                        byte[] PAC_Timestamp_Signature = GetKerberosHMACSHA1(ki_key, PAC_Timestamp);
                        packetASReq = NewPacketKerberosASREQ(kerberosUsernameBytes, kerberosRealmBytes, domainControllerBytes, nonce, PAC_ENC_Timestamp, PAC_Timestamp_Signature);
                        AS_REQ = ConvertFromPacketOrderedDictionary(packetASReq);
                        kerberosClientSend = AS_REQ;
                        kerberosClientStream.Write(kerberosClientSend, 0, kerberosClientSend.Length);
                        kerberosClientStream.Flush();
                        kerberosClientStream.Read(kerberosClientReceive, 0, kerberosClientReceive.Length);
                        asrepPayload = BitConverter.ToString(kerberosClientReceive).Replace("-", "");

                        kerberosClient.Close();
                        kerberosClientStream.Close();
                    }
                    else
                    {
                        try
                        {
                            Console.WriteLine("[+] Using current context of calling thread as client identity.");

                            KerberosRequestorSecurityToken ticket = new KerberosRequestorSecurityToken("DNS/" + domainController);

                            asrepKey = ticket.SecurityKey.GetSymmetricKey();
                            kerberosClientReceive = ticket.GetRequest();
                            asrepPayload = BitConverter.ToString(kerberosClientReceive).Replace("-", "");
                        }
                        catch
                        {
                            Console.WriteLine("[-] Kerberos authentication failed (current logon session)!");
                            authKrbSuccess = false;
                        }
                    }
                }

                if (asrepKey != null || (asrepPayload.Length > 0 && asrepPayload.Contains("A003020105A10302010B")))
                {
                    Console.WriteLine("[+] Kerberos preauthentication successful");
                    authKrbSuccess = true;
                }
                else if (asrepPayload.Length > 0 && asrepPayload.Contains("A003020105A10302011E"))
                {
                    Console.WriteLine("[-] Kerberos preauthentication error 0x" + asrepPayload.Substring(96, 2));
                    authKrbSuccess = false;
                }
                else
                {
                    Console.WriteLine("[-] Kerberos authentication failure");
                    authKrbSuccess = false;
                }

                if (authKrbSuccess)
                {
                    int ticketIndex = asrepPayload.IndexOf("A003020112A1030201");

                    if (ticketIndex < 0 || ticketIndex == 0)
                    {
                        Console.WriteLine("[-] ASREP payload did not contain necessary info");
                        return;
                    }

                    byte ticketKvn = kerberosClientReceive[ticketIndex / 2 + 9];

                    int ticketLength;
                    if (asrepPayload.Substring(ticketIndex + 22, 2) == "82")
                    {
                        ticketLength = (BitConverter.ToUInt16(new byte[] { kerberosClientReceive[ticketIndex / 2 + 13], kerberosClientReceive[ticketIndex / 2 + 12] }, 0)) - 4;
                    }
                    else
                    {
                        ticketLength = kerberosClientReceive[ticketIndex / 2 + 12] - 3;
                    }

                    byte[] ticket = kerberosClientReceive.Skip(ticketIndex / 2 + 18).Take(ticketLength).ToArray();
                    byte[] apReq = null;
                    byte[] kerberosSessionKey = null;
                    byte[] macFlags = null;
                    byte[] sequenceNumber = null;

                    if (kerberosTcpClient)
                    {
                        int cipherIndex = asrepPayload.Substring(ticketIndex + 1).IndexOf("A003020112A1030201") + ticketIndex + 1;

                        int cipherLength;
                        if (asrepPayload.Substring(cipherIndex + 22, 2) == "82")
                        {
                            cipherLength = (BitConverter.ToUInt16(new byte[] { kerberosClientReceive[cipherIndex / 2 + 13], kerberosClientReceive[cipherIndex / 2 + 12] }, 0)) - 4;
                        }
                        else
                        {
                            cipherLength = kerberosClientReceive[cipherIndex / 2 + 12] - 3;
                        }

                        byte[] cipher = kerberosClientReceive.Skip(cipherIndex / 2 + 18).Take(cipherLength).ToArray();
                        byte[] keKey = GetKerberosAES256UsageKey("encrypt", 3, baseKey);
                        byte[] asrepCleartext = UnprotectKerberosASREP(keKey, cipher.Take(cipher.Length - 12).ToArray());
                        Console.WriteLine("DEBUG asrepCleartext.Length = " + asrepCleartext.Length);
                        kerberosSessionKey = asrepCleartext.Skip(37).Take(32).ToArray();
                        keKey = GetKerberosAES256UsageKey("encrypt", 11, kerberosSessionKey);
                        byte[] kiKey = GetKerberosAES256UsageKey("integrity", 11, kerberosSessionKey);
                        byte[] subkey = NewRandomByteArray(32);
                        sequenceNumber = NewRandomByteArray(4);
                        OrderedDictionary packetAuthenticator = NewKerberosAuthenticator(kerberosRealmBytes, kerberosUsernameBytes, subkey, sequenceNumber);
                        byte[] authenticator = ConvertFromPacketOrderedDictionary(packetAuthenticator);
                        authenticator = NewRandomByteArray(16).Concat(authenticator).ToArray();
                        byte[] authenticatorEncrypted = ProtectKerberosAES256CTS(keKey, authenticator);
                        byte[] authenticatorSignature = GetKerberosHMACSHA1(kiKey, authenticator);
                        OrderedDictionary packetApreq = NewPacketKerberosAPREQ(kerberosRealmBytes, domainControllerBytes, new byte[] { ticketKvn }, ticket, authenticatorEncrypted, authenticatorSignature);
                        apReq = ConvertFromPacketOrderedDictionary(packetApreq);
                        Console.WriteLine("DEBUG macFlags will be set to 0x04");
                        macFlags = new byte[] { 0x04 };
                    }
                    else
                    {
                        apReq = kerberosClientReceive;
                        Console.WriteLine("DEBUG macFlags will be set to 0x00");
                        macFlags = new byte[] { 0x00 };
                    }

                    var packetDnsQuery = NewPacketDNSQueryTKEY(tkeyName, new byte[] { 0x00, 0xf9 }, apReq);
                    byte[] dnsQueryTKEY = ConvertFromPacketOrderedDictionary(packetDnsQuery);
                    TcpClient dnsClient = new TcpClient();
                    dnsClient.Client.ReceiveTimeout = 3000;

                    try
                    {
                        dnsClient.Connect(domainController, 53);
                    }
                    catch
                    {
                        Console.WriteLine($"{domainController} did not respond on TCP port 53");
                    }

                    bool tkeySuccess = false;

                    if (dnsClient.Connected)
                    {
                        NetworkStream dnsClientStream = dnsClient.GetStream();
                        byte[] dnsClientSend = dnsQueryTKEY;
                        dnsClientStream.Write(dnsClientSend, 0, dnsClientSend.Length);
                        dnsClientStream.Flush();
                        dnsClientStream.Read(dnsClientReceive, 0, dnsClientReceive.Length);
                        string tkeyPayload = BitConverter.ToString(dnsClientReceive).Replace("-", "");

                        if (tkeyPayload.Substring(8, 4) == "8000")
                        {
                            Console.WriteLine("[+] Kerberos TKEY query successful");
                            tkeySuccess = true;
                        }
                        else
                        {
                            Console.WriteLine($"[-] Kerberos TKEY query error 0x{tkeyPayload.Substring(8, 4)}");
                            tkeySuccess = false;
                        }

                        if (tkeySuccess)
                        {
                            byte[] acceptorSubkey = null;

                            if (kerberosTcpClient)
                            {
                                int cipherIndex = tkeyPayload.IndexOf("A003020112A2");

                                byte cipherLength = dnsClientReceive[cipherIndex / 2 + 8];
                                byte[] cipher = dnsClientReceive.Skip(cipherIndex / 2 + 8).Take(cipherLength).ToArray();
                                byte[] keKey = GetKerberosAES256UsageKey("encrypt", 12, kerberosSessionKey);
                                byte[] tkeyCleartext = UnprotectKerberosASREP(keKey, cipher.Take(cipher.Length - 12).ToArray());
                                acceptorSubkey = tkeyCleartext.Skip(59).Take(32).ToArray();
                            }
                            else
                            {
                                int sequenceIndex = tkeyPayload.IndexOf("FFFFFFFFFF00000000");
                                sequenceNumber = dnsClientReceive.Skip(sequenceIndex / 2 + 9).Take(4).ToArray();
                                acceptorSubkey = asrepKey;
                            }

                            byte[] kerberosAes256UsageKey = GetKerberosAES256UsageKey("checksum", 25, acceptorSubkey);
                            int timeSigned = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                            byte[] timeSignedBytes = (new byte[] { 0x00, 0x00 }).Concat(BitConverter.GetBytes(timeSigned).Reverse().ToArray()).ToArray();
                            byte[] transactionId = NewRandomByteArray(2);

                            OrderedDictionary packetDnsUpdate = NewPacketDNSUpdate(transactionId, zone, dnsName, dnsType, dnsTtl, dnsPreference, dnsPriority, dnsWeight, dnsPort, dnsData, timeSignedBytes, tkeyName);
                            byte[] dnsUpdateTsig = ConvertFromPacketOrderedDictionary(packetDnsUpdate);

                            OrderedDictionary packetDnsUpdateMac = NewPacketDNSUpdateMAC(macFlags, sequenceNumber, null);
                            byte[] dnsUpdateMac = ConvertFromPacketOrderedDictionary(packetDnsUpdateMac);

                            byte[] combinedDnsUpdateTsig = new byte[dnsUpdateTsig.Length + dnsUpdateMac.Length];
                            Array.Copy(dnsUpdateTsig, 0, combinedDnsUpdateTsig, 0, dnsUpdateTsig.Length);
                            Array.Copy(dnsUpdateMac, 0, combinedDnsUpdateTsig, dnsUpdateTsig.Length, dnsUpdateMac.Length);

                            byte[] checksum = GetKerberosHMACSHA1(kerberosAes256UsageKey, combinedDnsUpdateTsig);
                            OrderedDictionary finalPacketDnsUpdateMac = NewPacketDNSUpdateMAC(macFlags, sequenceNumber, checksum);
                            byte[] finalDnsUpdateMac = ConvertFromPacketOrderedDictionary(finalPacketDnsUpdateMac);

                            OrderedDictionary finalPacketDnsUpdate = NewPacketDNSUpdate(transactionId, zone, dnsName, dnsType, dnsTtl, dnsPreference, dnsPriority, dnsWeight, dnsPort, dnsData, timeSignedBytes, tkeyName, finalDnsUpdateMac);
                            byte[] finalDnsUpdateTsig = ConvertFromPacketOrderedDictionary(finalPacketDnsUpdate);

                            dnsClientStream.Write(finalDnsUpdateTsig, 0, finalDnsUpdateTsig.Length);
                            dnsClientStream.Flush();
                            dnsClientStream.Read(dnsClientReceive, 0, dnsClientReceive.Length);
                            string dnsUpdateResponseStatusFinal = GetDNSUpdateResponseStatus(dnsClientReceive);
                            Console.WriteLine(dnsUpdateResponseStatusFinal);
                            dnsClient.Close();
                            dnsClientStream.Close();
                        }
                    }
                }

            }
        }

        public static byte[] ConvertFromPacketOrderedDictionary(OrderedDictionary orderedDictionary)
        {
            List<byte> byteArray = new List<byte>();

            foreach (var field in orderedDictionary.Values)
            {
                byteArray.AddRange((byte[])field);
            }

            return byteArray.ToArray();
        }

        public static byte[] GetKerberosAES256UsageKey(string keyType, int usageNumber, byte[] baseKey)
        {
            byte[] padding = new byte[16]; // Initialized to zero (0x00 * 16)
            List<byte> listUsage = new List<byte>();

            byte[] usageConstant = null;

            if (keyType == "checksum")
            {
                switch (usageNumber)
                {
                    case 25:
                        usageConstant = new byte[] { 0x5d, 0xfb, 0x7d, 0xbf, 0x53, 0x68, 0xce, 0x69, 0x98, 0x4b, 0xa5, 0xd2, 0xe6, 0x43, 0x34, 0xba };
                        break;
                }
            }
            else if (keyType == "encrypt")
            {
                switch (usageNumber)
                {
                    case 1:
                        usageConstant = new byte[] { 0xae, 0x2c, 0x16, 0x0b, 0x04, 0xad, 0x50, 0x06, 0xab, 0x55, 0xaa, 0xd5, 0x6a, 0x80, 0x35, 0x5a };
                        break;
                    case 3:
                        usageConstant = new byte[] { 0xbe, 0x34, 0x9a, 0x4d, 0x24, 0xbe, 0x50, 0x0e, 0xaf, 0x57, 0xab, 0xd5, 0xea, 0x80, 0x75, 0x7a };
                        break;
                    case 4:
                        usageConstant = new byte[] { 0xc5, 0xb7, 0xdc, 0x6e, 0x34, 0xc7, 0x51, 0x12, 0xb1, 0x58, 0xac, 0x56, 0x2a, 0x80, 0x95, 0x8a };
                        break;
                    case 7:
                        usageConstant = new byte[] { 0xde, 0x44, 0xa2, 0xd1, 0x64, 0xe0, 0x51, 0x1e, 0xb7, 0x5b, 0xad, 0xd6, 0xea, 0x80, 0xf5, 0xba };
                        break;
                    case 11:
                        usageConstant = new byte[] { 0xfe, 0x54, 0xaa, 0x55, 0xa5, 0x02, 0x52, 0x2f, 0xbf, 0x5f, 0xaf, 0xd7, 0xea, 0x81, 0x75, 0xfa };
                        break;
                    case 12:
                        usageConstant = new byte[] { 0x05, 0xd7, 0xec, 0x76, 0xb5, 0x0b, 0x53, 0x33, 0xc1, 0x60, 0xb0, 0x58, 0x2a, 0x81, 0x96, 0x0b };
                        break;
                }
            }
            else if (keyType == "integrity")
            {
                switch (usageNumber)
                {
                    case 1:
                        usageConstant = new byte[] { 0x5b, 0x58, 0x2c, 0x16, 0x0a, 0x5a, 0xa8, 0x05, 0x56, 0xab, 0x55, 0xaa, 0xd5, 0x40, 0x2a, 0xb5 };
                        break;
                    case 4:
                        usageConstant = new byte[] { 0x72, 0xe3, 0xf2, 0x79, 0x3a, 0x74, 0xa9, 0x11, 0x5c, 0xae, 0x57, 0x2b, 0x95, 0x40, 0x8a, 0xe5 };
                        break;
                    case 7:
                        usageConstant = new byte[] { 0x8b, 0x70, 0xb8, 0xdc, 0x6a, 0x8d, 0xa9, 0x1d, 0x62, 0xb1, 0x58, 0xac, 0x55, 0x40, 0xeb, 0x15 };
                        break;
                    case 11:
                        usageConstant = new byte[] { 0xab, 0x80, 0xc0, 0x60, 0xaa, 0xaf, 0xaa, 0x2e, 0x6a, 0xb5, 0x5a, 0xad, 0x55, 0x41, 0x6b, 0x55 };
                        break;
                }
            }

            listUsage.AddRange(usageConstant);
            listUsage.AddRange(padding);

            usageConstant = listUsage.ToArray();

            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                aes.IV = new byte[16]; // Initialized to zero
                aes.KeySize = 256;
                aes.Key = baseKey;

                ICryptoTransform aesEncryptor = aes.CreateEncryptor();
                byte[] usageKey = aesEncryptor.TransformFinalBlock(usageConstant, 0, usageConstant.Length);

                return usageKey;
            }
        }

        public static byte[] GetKerberosAES256BaseKey(string salt, string password)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            byte[] passwordClearTextBytes = Encoding.UTF8.GetBytes(password);
            byte[] constant = new byte[] { 0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93, 0x5C, 0x9B, 0xDC, 0xDA, 0xD9, 0x5C, 0x98, 0x99, 0xC4, 0xCA, 0xE4, 0xDE, 0xE6, 0xD6, 0xCA, 0xE4 };

            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(passwordClearTextBytes, saltBytes, 4096))
            {
                byte[] pbkdf2Key = pbkdf2.GetBytes(32);

                using (AesManaged aes = new AesManaged())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    aes.IV = new byte[16]; // Initialized to zero
                    aes.KeySize = 256;
                    aes.Key = pbkdf2Key;

                    ICryptoTransform aesEncryptor = aes.CreateEncryptor();
                    byte[] baseKeyPart1 = aesEncryptor.TransformFinalBlock(constant, 0, constant.Length);
                    byte[] baseKeyPart2 = aesEncryptor.TransformFinalBlock(baseKeyPart1, 0, baseKeyPart1.Length);

                    byte[] baseKey = new byte[32];
                    Array.Copy(baseKeyPart1, 0, baseKey, 0, 16);
                    Array.Copy(baseKeyPart2, 0, baseKey, 16, 16);

                    return baseKey;
                }
            }
        }

        public static OrderedDictionary NewPacketKerberosASREQ(byte[] username, byte[] realm, byte[] nameString, byte[] nonce, byte[] pac = null, byte[] pacSignature = null)
        {
            DateTime timestamp = DateTime.UtcNow;
            DateTime till = timestamp.AddYears(20);
            string timestampString = timestamp.ToString("u").Replace("-", "").Replace(" ", "").Replace(":", "");
            string tillString = till.ToString("u").Replace("-", "").Replace(" ", "").Replace(":", "");
            byte[] timestampBytes = Encoding.UTF8.GetBytes(timestampString);
            byte[] tillBytes = Encoding.UTF8.GetBytes(tillString);


            int pacExtraLength = 0;
            if (pac != null)
            {
                pacExtraLength = 78;
            }

            byte[] nameString1Length = GetASN1LengthArray(nameString.Length);
            byte[] nameStringLength = GetASN1LengthArray(nameString.Length + nameString1Length.Length + 6);
            byte[] nameStringLength2 = GetASN1LengthArray(nameString.Length + nameString1Length.Length + nameStringLength.Length + 7);
            byte[] snameLength = GetASN1LengthArray(nameString.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + 13);
            byte[] snameLength2 = GetASN1LengthArray(nameString.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + snameLength.Length + 14);
            byte[] realmLength = GetASN1LengthArray(realm.Length);
            byte[] realmLength2 = GetASN1LengthArray(realm.Length + realmLength.Length + 1);
            byte[] cnameLength = GetASN1LengthArray(username.Length);
            byte[] cnameLength2 = GetASN1LengthArray(username.Length + cnameLength.Length + 1);
            byte[] cnameLength3 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + 2);
            byte[] cnameLength4 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + 8);
            byte[] cnameLength5 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + cnameLength4.Length + 9);

            int totalGroupedLength = nameString.Length
                + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + snameLength.Length + snameLength2.Length + realm.Length + realmLength.Length
                + realmLength2.Length + username.Length + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + cnameLength4.Length + cnameLength5.Length;

            byte[] requestBodyLength = GetASN1LengthArrayLong(totalGroupedLength + 86);
            byte[] requestBodyLength2 = GetASN1LengthArrayLong(totalGroupedLength + requestBodyLength.Length + 87);
            byte[] messageLength = GetASN1LengthArrayLong(totalGroupedLength + requestBodyLength.Length + requestBodyLength2.Length + pacExtraLength + 114);
            byte[] messageLength2 = GetASN1LengthArrayLong(totalGroupedLength + requestBodyLength.Length + requestBodyLength2.Length + messageLength.Length + pacExtraLength + 115);
            byte[] asRequestLength = BitConverter.GetBytes(totalGroupedLength + requestBodyLength.Length + requestBodyLength2.Length + messageLength.Length + messageLength2.Length + pacExtraLength + 116).Reverse().ToArray();

            OrderedDictionary kerberosASREQ = new OrderedDictionary();
            kerberosASREQ.Add("Length", asRequestLength);
            kerberosASREQ.Add("Message_Encoding", new byte[] { 0x6a }.Concat(messageLength2).Concat(new byte[] { 0x30 }).Concat(messageLength).ToArray());
            kerberosASREQ.Add("Message_PVNO_Encoding", new byte[] { 0xa1, 0x03, 0x02, 0x01 });
            kerberosASREQ.Add("Message_PVNO", new byte[] { 0x05 });
            kerberosASREQ.Add("Message_MSGType_Encoding", new byte[] { 0xa2, 0x03, 0x02, 0x01 });
            kerberosASREQ.Add("Message_MSGType", new byte[] { 0x0a });

            if (pac != null)
            {
                kerberosASREQ.Add("Message_PAData_Encoding", new byte[] { 0xa3, 0x5c, 0x30, 0x5a, 0x30, 0x4c, 0xa1, 0x03, 0x02, 0x01, 0x02 });
                kerberosASREQ.Add("Message_PAData0_Type_Encoding", new byte[] { 0xa2, 0x45, 0x04, 0x43, 0x30, 0x41, 0xa0, 0x03, 0x02, 0x01 });
                kerberosASREQ.Add("Message_PAData0_Type", new byte[] { 0x12 });
                kerberosASREQ.Add("Message_PAData0_Value_Encoding", new byte[] { 0xa2, 0x3a, 0x04, 0x38 });
                kerberosASREQ.Add("Message_PAData0_Value", pac);
                kerberosASREQ.Add("Message_PAData0_Signature", pacSignature);
                kerberosASREQ.Add("Message_PAData1_Type_Encoding", new byte[] { 0x30, 0x0a, 0xa1, 0x04, 0x02, 0x02 });
            }
            else
            {
                kerberosASREQ.Add("Message_PAData_Encoding", new byte[] { 0xa3, 0x0e, 0x30, 0x0c, 0x30, 0x0a });
                kerberosASREQ.Add("Message_PAData1_Type_Encoding", new byte[] { 0xa1, 0x04, 0x02, 0x02 });
            }

            kerberosASREQ.Add("Message_PAData1_Type", new byte[] { 0x00, 0x95 });
            kerberosASREQ.Add("Message_PAData1_Value_Encoding", new byte[] { 0xa2, 0x02, 0x04 });
            kerberosASREQ.Add("Message_PAData1_Value", new byte[] { 0x00 });
            kerberosASREQ.Add("Message_REQBody_Encoding", new byte[] { 0xa4 }.Concat(requestBodyLength2).Concat(new byte[] { 0x30 }).Concat(requestBodyLength).ToArray());
            kerberosASREQ.Add("Message_REQBody_KDCOptions_Encoding", new byte[] { 0xa0, 0x07, 0x03, 0x05 });
            kerberosASREQ.Add("Message_REQBody_KDCOptions_Padding", new byte[] { 0x00 });
            kerberosASREQ.Add("Message_REQBody_KDCOptions", new byte[] { 0x50, 0x00, 0x00, 0x00 });
            kerberosASREQ.Add("Message_REQBody_CName_Encoding", new byte[] { 0xa1 }.Concat(cnameLength5).Concat(new byte[] { 0x30 }).Concat(cnameLength4).ToArray());
            kerberosASREQ.Add("Message_REQBody_CName_NameType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosASREQ.Add("Message_REQBody_CName_NameType", new byte[] { 0x01 });
            kerberosASREQ.Add("Message_REQBody_CName_NameString_Encoding", new byte[] { 0xa1 }.Concat(cnameLength3).Concat(new byte[] { 0x30 }).Concat(cnameLength2).Concat(new byte[] { 0x1b }).Concat(cnameLength).ToArray());
            kerberosASREQ.Add("Message_REQBody_CName_NameString", username);
            kerberosASREQ.Add("Message_REQBody_Realm_Encoding", new byte[] { 0xa2 }.Concat(realmLength2).Concat(new byte[] { 0x1b }).Concat(realmLength).ToArray());
            kerberosASREQ.Add("Message_REQBody_Realm", realm);
            kerberosASREQ.Add("Message_REQBody_SName_Encoding", new byte[] { 0xa3 }.Concat(snameLength2).Concat(new byte[] { 0x30 }).Concat(snameLength).ToArray());
            kerberosASREQ.Add("Message_REQBody_SName_NameType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosASREQ.Add("Message_REQBody_SName_NameType", new byte[] { 0x01 });
            kerberosASREQ.Add("Message_REQBody_SName_NameString_Encoding", new byte[] { 0xa1 }.Concat(nameStringLength2).Concat(new byte[] { 0x30 }).Concat(nameStringLength).ToArray());
            kerberosASREQ.Add("Message_REQBody_SName_NameString0_Encoding", new byte[] { 0x1b, 0x03 });
            kerberosASREQ.Add("Message_REQBody_SName_NameString0", new byte[] { 0x44, 0x4e, 0x53 });
            kerberosASREQ.Add("Message_REQBody_SName_NameString1_Encoding", new byte[] { 0x1b }.Concat(nameString1Length).ToArray()); //50
            kerberosASREQ.Add("Message_REQBody_SName_NameString1", nameString);
            kerberosASREQ.Add("Message_REQBody_Till_Encoding", new byte[] { 0xa5, 0x11, 0x18, 0x0f });
            kerberosASREQ.Add("Message_REQBody_Till", tillBytes);
            kerberosASREQ.Add("Message_REQBody_Nonce_Encoding", new byte[] { 0xa7, 0x06, 0x02, 0x04 });
            kerberosASREQ.Add("Message_REQBody_Nonce", nonce);
            kerberosASREQ.Add("Message_REQBody_EType_Encoding", new byte[] { 0xa8, 0x15, 0x30, 0x13 });
            kerberosASREQ.Add("Message_REQBody_EType", new byte[] { 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18, 0x02, 0x02, 0xff, 0x79, 0x02, 0x01, 0x03 });

            return kerberosASREQ;
        }

        public static OrderedDictionary NewPacketKerberosAPREQ(byte[] realm, byte[] spn, byte[] kvno, byte[] ticket, byte[] authenticator, byte[] authenticatorSignature)
        {
            authenticator = authenticator.Concat(authenticatorSignature).ToArray();
            int parameterLength = realm.Length + spn.Length + ticket.Length + authenticator.Length;

            byte[] authenticatorLength = GetASN1LengthArrayLong(authenticator.Length);
            byte[] authenticatorLength2 = GetASN1LengthArrayLong(authenticator.Length + authenticatorLength.Length + 1);
            byte[] authenticatorLength3 = GetASN1LengthArrayLong(authenticator.Length + authenticatorLength.Length + authenticatorLength2.Length + 7);
            byte[] authenticatorLength4 = GetASN1LengthArrayLong(authenticator.Length + authenticatorLength.Length + authenticatorLength2.Length + authenticatorLength3.Length + 8);

            byte[] ticketLength = GetASN1LengthArrayLong(ticket.Length);
            byte[] ticketLength2 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + 1);
            byte[] ticketLength3 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + ticketLength2.Length + 12);
            byte[] ticketLength4 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + 13);

            byte[] nameString1Length = GetASN1LengthArray(spn.Length);
            byte[] nameStringLength = GetASN1LengthArray(spn.Length + nameString1Length.Length + 4);
            byte[] nameStringLength2 = GetASN1LengthArray(spn.Length + nameString1Length.Length + nameStringLength.Length + 5);

            byte[] sNameLength = GetASN1LengthArray(spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + 4);
            byte[] sNameLength2 = GetASN1LengthArray(spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + 5);
            byte[] sNameLength3 = GetASN1LengthArray(spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + 11);
            byte[] sNameLength4 = GetASN1LengthArray(spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + 12);

            byte[] realmLength = GetASN1LengthArray(realm.Length);
            byte[] realmLength2 = GetASN1LengthArray(realm.Length + realmLength.Length + 1);

            byte[] ticketLength5 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realm.Length + realmLength.Length + realmLength2.Length + 34);
            byte[] ticketLength6 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realm.Length + realmLength.Length + realmLength2.Length + ticketLength5.Length + 35);
            byte[] ticketLength7 = GetASN1LengthArrayLong(ticket.Length + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + spn.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realm.Length + realmLength.Length + realmLength2.Length + ticketLength5.Length + ticketLength6.Length + 36);

            byte[] apReqLength = GetASN1LengthArrayLong(parameterLength + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realmLength.Length + realmLength2.Length + ticketLength5.Length + ticketLength6.Length + ticketLength7.Length + 73);
            byte[] apReqLength2 = GetASN1LengthArrayLong(parameterLength + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realmLength.Length + realmLength2.Length + ticketLength5.Length + ticketLength6.Length + ticketLength7.Length + apReqLength.Length + 74);

            byte[] length = GetASN1LengthArrayLong(parameterLength + ticketLength.Length + ticketLength2.Length + ticketLength3.Length + ticketLength4.Length + nameString1Length.Length + nameStringLength.Length + nameStringLength2.Length + sNameLength.Length + sNameLength2.Length + sNameLength3.Length + sNameLength4.Length + realmLength.Length + realmLength2.Length + ticketLength5.Length + ticketLength6.Length + ticketLength7.Length + apReqLength.Length + apReqLength2.Length + 88);

            OrderedDictionary kerberosAPREQ = new OrderedDictionary();

            kerberosAPREQ.Add("Length", new byte[] { 0x60 }.Concat(length).ToArray());
            kerberosAPREQ.Add("MechToken_ThisMech", new byte[] { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 });
            kerberosAPREQ.Add("MechToken_TokenID", new byte[] { 0x01, 0x00 });
            kerberosAPREQ.Add("APReq_Encoding", new byte[] { 0x6e }.Concat(apReqLength2).Concat(new byte[] { 0x30 }).Concat(apReqLength).ToArray());
            kerberosAPREQ.Add("PVNO_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("PVNO", new byte[] { 0x05 });
            kerberosAPREQ.Add("MSGType_Encoding", new byte[] { 0xa1, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("MSGType", new byte[] { 0x0e });
            kerberosAPREQ.Add("Padding_Encoding", new byte[] { 0xa2, 0x07, 0x03, 0x05 });
            kerberosAPREQ.Add("Padding", new byte[] { 0x00 });
            kerberosAPREQ.Add("APOptions", new byte[] { 0x20, 0x00, 0x00, 0x00 });
            kerberosAPREQ.Add("Ticket_Encoding", new byte[] { 0xa3 }.Concat(ticketLength7).Concat(new byte[] { 0x61 }).Concat(ticketLength6).Concat(new byte[] { 0x30 }).Concat(ticketLength5).ToArray());
            kerberosAPREQ.Add("Ticket_TKTVNO_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("Ticket_TKTVNO", new byte[] { 0x05 });
            kerberosAPREQ.Add("Ticket_Realm_Encoding", new byte[] { 0xa1 }.Concat(realmLength2).Concat(new byte[] { 0x1b }).Concat(realmLength).ToArray());
            kerberosAPREQ.Add("Ticket_Realm", realm);
            kerberosAPREQ.Add("Ticket_SName_Encoding", new byte[] { 0xa2 }.Concat(sNameLength4).Concat(new byte[] { 0x30 }).Concat(sNameLength3).ToArray());
            kerberosAPREQ.Add("Ticket_SName_NameType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("Ticket_SName_NameType", new byte[] { 0x01 });
            kerberosAPREQ.Add("Ticket_SName_NameString_Encoding", new byte[] { 0xa1 }.Concat(sNameLength2).Concat(new byte[] { 0x30 }).Concat(sNameLength).ToArray());
            kerberosAPREQ.Add("Ticket_SName_NameString0_Encoding", new byte[] { 0x1b, 0x03 });
            kerberosAPREQ.Add("Ticket_SName_NameString0", new byte[] { 0x44, 0x4e, 0x53 });
            kerberosAPREQ.Add("Ticket_SName_NameString1_Encoding", new byte[] { 0x1b }.Concat(nameString1Length).ToArray());
            kerberosAPREQ.Add("Ticket_SName_NameString1", spn);
            kerberosAPREQ.Add("Ticket_EncPart_Encoding", new byte[] { 0xa3 }.Concat(ticketLength4).Concat(new byte[] { 0x30 }).Concat(ticketLength3).ToArray());
            kerberosAPREQ.Add("Ticket_EncPart_EType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("Ticket_EncPart_EType", new byte[] { 0x12 });
            kerberosAPREQ.Add("Ticket_EncPart_KVNO_Encoding", new byte[] { 0xa1, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("Ticket_EncPart_KVNO", kvno);
            kerberosAPREQ.Add("Ticket_EncPart_Cipher_Encoding", new byte[] { 0xa2 }.Concat(ticketLength2).Concat(new byte[] { 0x04 }).Concat(ticketLength).ToArray());
            kerberosAPREQ.Add("Ticket_EncPart_Cipher", ticket);
            kerberosAPREQ.Add("Authenticator_Encoding", new byte[] { 0xa4 }.Concat(authenticatorLength4).Concat(new byte[] { 0x30 }).Concat(authenticatorLength3).ToArray());
            kerberosAPREQ.Add("Authenticator_EType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAPREQ.Add("Authenticator_EType", new byte[] { 0x12 });
            kerberosAPREQ.Add("Authenticator_Cipher_Encoding", new byte[] { 0xa2 }.Concat(authenticatorLength2).Concat(new byte[] { 0x04 }).Concat(authenticatorLength).ToArray());
            kerberosAPREQ.Add("Authenticator_Cipher", authenticator);

            return kerberosAPREQ;
        }

        public static byte[] UnprotectKerberosASREP(byte[] key, byte[] encryptedData)
        {
            int finalBlockLength = (int)Math.Truncate((decimal)encryptedData.Length % 16);

            byte[] finalBlock = new byte[16];
            Array.Copy(encryptedData, encryptedData.Length - finalBlockLength, finalBlock, 0, finalBlockLength);

            byte[] penultimateBlock = encryptedData.Skip(encryptedData.Length - finalBlockLength - 16).Take(16).ToArray();

            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                aes.IV = new byte[16];
                aes.KeySize = 256;
                aes.Key = key;

                ICryptoTransform aesDecryptor = aes.CreateDecryptor();
                byte[] penultimateBlockCleartext = aesDecryptor.TransformFinalBlock(penultimateBlock, 0, penultimateBlock.Length);

                byte[] finalBlockPadding = penultimateBlockCleartext.Skip(finalBlockLength).Take(16 - finalBlockLength).ToArray();

                finalBlock = finalBlock.Take(finalBlockLength).Concat(finalBlockPadding).ToArray();

                List<byte> ctsEncryptedDataList = new List<byte>();
                ctsEncryptedDataList.AddRange(encryptedData.Take(encryptedData.Count() - 16 - finalBlockLength));
                byte[] ctsEncryptedData = ctsEncryptedDataList.Concat(finalBlock).Concat(penultimateBlock).ToArray();

                byte[] cleartext = aesDecryptor.TransformFinalBlock(ctsEncryptedData, 0, ctsEncryptedData.Length);

                return cleartext;
            }
        }

        public static byte[] NewKerberosPACTimestamp(byte[] key)
        {
            byte[] timestamp = GetKerberosTimestampUTC();
            byte[] confounder = new byte[16];
            Random random = new Random();

            for (int i = 0; i < confounder.Length; i++)
            {
                confounder[i] = (byte)random.Next(1, 255);
            }

            byte[] PACTimestamp = confounder.Concat(new byte[] { 0x30, 0x1a, 0xa0, 0x11, 0x18, 0x0f })
                .Concat(timestamp)
                .Concat(new byte[] { 0xa1, 0x05, 0x02, 0x03, 0x01, 0x70, 0x16 }).ToArray();

            return PACTimestamp;
        }

        public static OrderedDictionary NewKerberosAuthenticator(byte[] realm, byte[] username, byte[] subKey, byte[] sequenceNumber)
        {
            int parameterLength = realm.Length + username.Length + subKey.Length;
            byte[] subkeyLength = GetASN1LengthArray(subKey.Length);
            byte[] subkeyLength2 = GetASN1LengthArray(subKey.Length + subkeyLength.Length + 1);
            byte[] subkeyLength3 = GetASN1LengthArray(subKey.Length + subkeyLength.Length + subkeyLength2.Length + 7);
            byte[] subkeyLength4 = GetASN1LengthArray(subKey.Length + subkeyLength.Length + subkeyLength2.Length + subkeyLength3.Length + 8);
            byte[] cnameLength = GetASN1LengthArray(username.Length);
            byte[] cnameLength2 = GetASN1LengthArray(username.Length + cnameLength.Length + 1);
            byte[] cnameLength3 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + 2);
            byte[] cnameLength4 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + 8);
            byte[] cnameLength5 = GetASN1LengthArray(username.Length + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + cnameLength4.Length + 9);
            byte[] realmLength = GetASN1LengthArray(realm.Length);
            byte[] realmLength2 = GetASN1LengthArray(realm.Length + realmLength.Length + 1);
            byte[] authenticatorLength = GetASN1LengthArrayLong(parameterLength + 99 + realmLength.Length + realmLength2.Length 
                + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + cnameLength4.Length + cnameLength5.Length 
                + subkeyLength.Length + subkeyLength2.Length + subkeyLength3.Length + subkeyLength4.Length);
            byte[] authenticatorLength2 = GetASN1LengthArrayLong(parameterLength + 100 + realmLength.Length + realmLength2.Length 
                + cnameLength.Length + cnameLength2.Length + cnameLength3.Length + cnameLength4.Length + cnameLength5.Length + subkeyLength.Length 
                + subkeyLength2.Length + subkeyLength3.Length + subkeyLength4.Length + authenticatorLength.Length);

            OrderedDictionary kerberosAuthenticator = new OrderedDictionary();
            kerberosAuthenticator.Add("Encoding", new byte[] { 0x62 }.Concat(authenticatorLength2).Concat(new byte[] { 0x30 }).Concat(authenticatorLength).ToArray());
            kerberosAuthenticator.Add("AuthenticatorVNO_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAuthenticator.Add("AuthenticatorVNO", new byte[] { 0x05 });
            kerberosAuthenticator.Add("CRealm_Encoding", new byte[] { 0xa1 }.Concat(realmLength2).Concat(new byte[] { 0x1b }).Concat(realmLength).ToArray());
            kerberosAuthenticator.Add("CRealm", realm);
            kerberosAuthenticator.Add("CName_Encoding", new byte[] { 0xa2 }.Concat(cnameLength5).Concat(new byte[] { 0x30 }).Concat(cnameLength4).ToArray());
            kerberosAuthenticator.Add("CName_NameType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAuthenticator.Add("CName_NameType", new byte[] { 0x01 });
            kerberosAuthenticator.Add("CName_CNameString_Encoding", new byte[] { 0xa1 }.Concat(cnameLength3).Concat(new byte[] { 0x30 }).Concat(cnameLength2).Concat(new byte[] { 0x1b }).Concat(cnameLength).ToArray());
            kerberosAuthenticator.Add("CName_CNameString", username);
            kerberosAuthenticator.Add("CKSum_Encoding", new byte[] { 0xa3, 0x25, 0x30, 0x23, 0xa0, 0x05, 0x02, 0x03 });
            kerberosAuthenticator.Add("CKSum_CKSumType", new byte[] { 0x00, 0x80, 0x03 });
            kerberosAuthenticator.Add("CKSum_Length_Encoding", new byte[] { 0xa1, 0x1a, 0x04, 0x18 });
            kerberosAuthenticator.Add("CKSum_Length", new byte[] { 0x10, 0x00, 0x00, 0x00 });
            kerberosAuthenticator.Add("CKSum_Bnd", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            kerberosAuthenticator.Add("CKSum_Flags", new byte[] { 0x36, 0x01, 0x00, 0x00 });
            kerberosAuthenticator.Add("CKSum_CUSec_Encoding", new byte[] { 0xa4, 0x05, 0x02, 0x03 });
            kerberosAuthenticator.Add("CKSum_CUSec", GetKerberosMicrosecond());
            kerberosAuthenticator.Add("CKSum_CTime_Encoding", new byte[] { 0xa5, 0x11, 0x18, 0x0f });
            kerberosAuthenticator.Add("CKSum_CTime", GetKerberosTimestampUTC());
            kerberosAuthenticator.Add("CKSum_Subkey_Encoding", new byte[] { 0xa6 }.Concat(subkeyLength4).Concat(new byte[] { 0x30 }).Concat(subkeyLength3).ToArray());
            kerberosAuthenticator.Add("CKSum_Subkey_KeyType_Encoding", new byte[] { 0xa0, 0x03, 0x02, 0x01 });
            kerberosAuthenticator.Add("CKSum_Subkey_KeyType", new byte[] { 0x12 });
            kerberosAuthenticator.Add("CKSum_Subkey_KeyValue_Encoding", new byte[] { 0xa1 }.Concat(subkeyLength2).Concat(new byte[] { 0x04 }).Concat(subkeyLength).ToArray());
            kerberosAuthenticator.Add("CKSum_Subkey_KeyValue", subKey);
            kerberosAuthenticator.Add("CKSum_SEQNumber_Encoding", new byte[] { 0xa7, 0x06, 0x02, 0x04 });
            kerberosAuthenticator.Add("CKSum_SEQNumber", sequenceNumber);

            return kerberosAuthenticator;
        }

        public static byte[] GetKerberosTimestampUTC()
        {
            DateTime timestamp = DateTime.UtcNow;
            string timestampString = timestamp.ToString("u").Replace("-", "").Replace(" ", "").Replace(":", "");
            byte[] timestampBytes = Encoding.UTF8.GetBytes(timestampString);

            return timestampBytes;
        }

        public static byte[] GetKerberosMicrosecond()
        {
            int microseconds = Int32.Parse(DateTime.Now.ToString("ffffff"));
            byte[] microsecondsBytes = BitConverter.GetBytes(microseconds);

            return new byte[] { microsecondsBytes[0], microsecondsBytes[1], microsecondsBytes[2] };
        }

        public static byte[] ProtectKerberosAES256CTS(byte[] key, byte[] data)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                aes.IV = new byte[16]; // Initialized to zero
                aes.KeySize = 256;
                aes.Key = key;

                using (ICryptoTransform aesEncryptor = aes.CreateEncryptor())
                {
                    List<byte> encryptedData = new List<byte>(aesEncryptor.TransformFinalBlock(data, 0, data.Length));
                    int blockCount = (int)Math.Ceiling(encryptedData.Count() / 16.0);

                    List<byte> encDataReordered = new List<byte>();

                    if (blockCount > 2)
                    {
                        encDataReordered.AddRange(encryptedData.Take(encryptedData.Count() - 32));
                        encDataReordered.AddRange(encryptedData.Skip(encryptedData.Count() - 16).Take(16));
                        encDataReordered.AddRange(encryptedData.Skip(encryptedData.Count() - 32).Take(16));
                    }
                    else if (blockCount == 2)
                    {
                        encDataReordered.AddRange(encryptedData.Skip(16).Take(16));
                        encDataReordered.AddRange(encryptedData.Take(16));
                    }

                    int finalBlockLength = (int)Math.Truncate(data.Length % 16.0);

                    if (finalBlockLength != 0)
                    {
                        int removeCount = 16 - finalBlockLength;
                        encryptedData = new List<byte>(encDataReordered.Take(encDataReordered.Count() - removeCount));
                    }
                    else
                    {
                        encryptedData = encDataReordered;
                    }

                    return encryptedData.ToArray();
                }
            }
        }

        public static byte[] GetKerberosHMACSHA1(byte[] key, byte[] data)
        {
            HMACSHA1 hmacSHA1 = new HMACSHA1(key);
            byte[] hash = hmacSHA1.ComputeHash(data);
            byte[] truncatedHash = hash.Take(12).ToArray();

            return truncatedHash;
        }

        public static byte[] GetASN1LengthArray(int length)
        {
            byte[] asn1 = BitConverter.GetBytes(length);

            if (asn1[1] == 0)
            {
                return new byte[] { asn1[0] };
            }
            else
            {
                return new byte[] { asn1[1], asn1[0] };
            }
        }

        public static byte[] GetASN1LengthArrayLong(int length)
        {
            byte[] asn1 = BitConverter.GetBytes(length);

            if (asn1[1] == 0)
            {
                byte[] result = new byte[2];
                result[0] = 0x81;
                result[1] = asn1[0];
                return result;
            }
            else
            {
                byte[] result = new byte[3];
                result[0] = 0x82;
                result[1] = asn1[1];
                result[2] = asn1[0];
                return result;
            }
        }

        public static byte[] NewRandomByteArray(int length, int minimum = 1, int maximum = 255)
        {
            List<byte> randomBytesList = new List<byte>();
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                randomBytesList.Add((byte)random.Next(minimum, maximum));
            }
            byte[] randomByteArray = randomBytesList.ToArray();

            return randomByteArray;
        }

        public static byte[] NewDNSNameArray(string name)
        {
            char[] characterArray = name.ToCharArray();
            int[] indexArray = Enumerable.Range(0, characterArray.Length).Where(index => characterArray[index] == '.').ToArray();
            byte[] nameArray = new byte[0];

            if (indexArray.Length > 0)
            {
                int nameStartIndex = 0;

                foreach (int index in indexArray)
                {
                    int nameEndLength = index - nameStartIndex;
                    nameArray = nameArray.Concat(new byte[] { (byte)nameEndLength }).ToArray();
                    nameArray = nameArray.Concat(Encoding.UTF8.GetBytes(name.Substring(nameStartIndex, nameEndLength))).ToArray();
                    nameStartIndex = index + 1;
                }

                nameArray = nameArray.Concat(new byte[] { (byte)(name.Length - nameStartIndex) }).ToArray();
                nameArray = nameArray.Concat(Encoding.UTF8.GetBytes(name.Substring(nameStartIndex))).ToArray();
            }
            else
            {
                nameArray = nameArray.Concat(new byte[] { (byte)name.Length }).ToArray();
                nameArray = nameArray.Concat(Encoding.UTF8.GetBytes(name)).ToArray();
            }

            return nameArray;
        }

        public static OrderedDictionary NewPacketDNSQuery(string name, string type)
        {
            byte[] queryType;

            switch (type)
            {
                case "A":
                    queryType = new byte[] { 0x00, 0x01 };
                    break;

                case "AAAA":
                    queryType = new byte[] { 0x00, 0x1C };
                    break;

                case "CNAME":
                    queryType = new byte[] { 0x00, 0x05 };
                    break;

                case "MX":
                    queryType = new byte[] { 0x00, 0x0F };
                    break;

                case "PTR":
                    queryType = new byte[] { 0x00, 0x0C };
                    break;

                case "SRV":
                    queryType = new byte[] { 0x00, 0x21 };
                    break;

                case "TXT":
                    queryType = new byte[] { 0x00, 0x10 };
                    break;

                default:
                    Console.WriteLine("[-] Invalid DNS query type.");
                    return new OrderedDictionary();
            }

            byte[] nameBytes = NewDNSNameArray(name);
            byte[] nameWithNullTerminator = new byte[nameBytes.Length + 1];
            Array.Copy(nameBytes, nameWithNullTerminator, nameBytes.Length);
            nameWithNullTerminator[nameBytes.Length] = 0x00;

            byte[] length = BitConverter.GetBytes(nameWithNullTerminator.Length + 16);
            byte[] transactionId = NewRandomByteArray(2);

            OrderedDictionary dnsQuery = new OrderedDictionary
            {
                { "Length", new byte[] { length[1], length[0] } },
                { "TransactionID", transactionId },
                { "Flags", new byte[] { 0x01, 0x00 } },
                { "Questions", new byte[] { 0x00, 0x01 } },
                { "AnswerRRs", new byte[] { 0x00, 0x00 } },
                { "AuthorityRRs", new byte[] { 0x00, 0x00 } },
                { "AdditionalRRs", new byte[] { 0x00, 0x00 } },
                { "Queries_Name", nameWithNullTerminator },
                { "Queries_Type", queryType },
                { "Queries_Class", new byte[] { 0x00, 0x01 } }
            };

            return dnsQuery;
        }

        public static OrderedDictionary NewPacketDNSQueryTKEY(byte[] name, byte[] type, byte[] apReq)
        {
            byte[] transactionId = NewRandomByteArray(2);
            byte[] length;
            byte[] rdLength = null;
            byte[] inception = null;
            byte[] keySize = null;
            byte[] mechtokenLength = null;
            byte[] mechtokenLength2 = null;
            byte[] innerContextTokenLength = null;
            byte[] innerContextTokenLength2 = null;
            byte[] spnegoLength = null;


            if (apReq != null)
            {
                mechtokenLength = GetASN1LengthArrayLong(apReq.Length);
                mechtokenLength2 = GetASN1LengthArrayLong(apReq.Length + mechtokenLength.Length + 1);
                innerContextTokenLength = GetASN1LengthArrayLong(apReq.Length + mechtokenLength.Length + mechtokenLength2.Length + 17);
                innerContextTokenLength2 = GetASN1LengthArrayLong(apReq.Length + mechtokenLength.Length + mechtokenLength2.Length + innerContextTokenLength.Length + 18);
                spnegoLength = GetASN1LengthArrayLong(apReq.Length + mechtokenLength.Length + mechtokenLength2.Length + innerContextTokenLength.Length + innerContextTokenLength2.Length + 27);
                int groupedLength = apReq.Length + mechtokenLength.Length + mechtokenLength2.Length + innerContextTokenLength.Length + innerContextTokenLength2.Length + spnegoLength.Length + 25;
                keySize = BitConverter.GetBytes(groupedLength + 3).Take(2).Reverse().ToArray();
                rdLength = BitConverter.GetBytes(groupedLength + keySize.Length + 27).Take(2).Reverse().ToArray();
                long inceptionTime = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                inception = BitConverter.GetBytes(inceptionTime).Take(4).Reverse().ToArray();
                length = BitConverter.GetBytes(groupedLength + name.Length + 57).Take(2).Reverse().ToArray();
            }
            else
            {
                length = BitConverter.GetBytes(name.Length + 16).Reverse().Skip(2).ToArray();
            }

            OrderedDictionary dnsQueryTKEY = new OrderedDictionary();
            dnsQueryTKEY.Add("Length", length);
            dnsQueryTKEY.Add("TransactionID", transactionId);
            dnsQueryTKEY.Add("Flags", new byte[] { 0x00, 0x00 });
            dnsQueryTKEY.Add("Questions", new byte[] { 0x00, 0x01 });
            dnsQueryTKEY.Add("AnswerRRs", new byte[] { 0x00, 0x00 });
            dnsQueryTKEY.Add("AuthorityRRs", new byte[] { 0x00, 0x00 });

            if (apReq != null)
            {
                dnsQueryTKEY.Add("AdditionalRRs", new byte[] { 0x00, 0x01 });
            }
            else
            {
                dnsQueryTKEY.Add("AdditionalRRs", new byte[] { 0x00, 0x00 });
            }

            dnsQueryTKEY.Add("Queries_Name", name);
            dnsQueryTKEY.Add("Queries_Type", type);
            dnsQueryTKEY.Add("Queries_Class", new byte[] { 0x00, 0xff });

            if (apReq != null)
            {
                dnsQueryTKEY.Add("Queries_AdditionalRecords_Name", new byte[] { 0xc0, 0x0c });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_Type", new byte[] { 0x00, 0xf9 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_Class", new byte[] { 0x00, 0xff });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_TTL", new byte[] { 0x00, 0x00, 0x00, 0x00 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RDLength", rdLength);
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_Algorithm", new byte[] { 0x08, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67, 0x00 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_Inception", inception);
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_Expiration", inception);
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_Mode", new byte[] { 0x00, 0x03 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_Error", new byte[] { 0x00, 0x00 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_KeySize", keySize);
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_Encoding", new byte[] { 0x60 }.Concat(spnegoLength).ToArray());
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_ThisMech", new byte[] { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_InnerContextToken_Encoding", new byte[] { 0xa0 }.Concat(innerContextTokenLength2).Concat(new byte[] { 0x30 }).Concat(innerContextTokenLength).ToArray());
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_InnerContextToken_MechTypes_Encoding", new byte[] { 0xa0, 0x0d, 0x30, 0x0b });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_InnerContextToken_MechType0", new byte[] { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 });
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_InnerContextToken_MechToken_Encoding", new byte[] { 0xa2 }.Concat(mechtokenLength2).Concat(new byte[] { 0x04 }).Concat(mechtokenLength).ToArray());
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_SPNEGO_InnerContextToken_MechToken_Token", apReq);
                dnsQueryTKEY.Add("Queries_AdditionalRecords_RData_OtherSize", new byte[] { 0x00, 0x00 });
            }

            return dnsQueryTKEY;
        }

        public static OrderedDictionary NewPacketDNSUpdate(byte[] transactionID, string zone, string name, string type, int ttl, int? preference, int? priority, int? weight, int? port, string data, byte[] timeSigned = null, byte[] tKeyname = null, byte[] mac = null)
        {
            byte[] classBytes;
            bool add = false;

            if (!string.IsNullOrEmpty(data))
            {
                add = true;
                classBytes = new byte[] { 0x00, 0x01 };
            }
            else
            {
                classBytes = new byte[] { 0x00, 0xff };
                ttl = 0;
            }

            byte[] typeBytes = null;
            byte[] dataBytes = null;
            byte[] txtLengthBytes = null;
            byte[] preferenceBytes = null;
            int extraLength = 0;

            switch (type.ToUpper())
            {
                case "A":
                    typeBytes = new byte[] { 0x00, 0x01 };
                    if (!string.IsNullOrEmpty(data) && IPAddress.TryParse(data, out var ipAddress))
                    {
                        dataBytes = ipAddress.GetAddressBytes();
                    }
                    else if (!string.IsNullOrEmpty(data))
                    {
                        dataBytes = Encoding.UTF8.GetBytes(data);
                    }
                    break;

                case "AAAA":
                    typeBytes = new byte[] { 0x00, 0x1c };
                    if (!string.IsNullOrEmpty(data) && IPAddress.TryParse(data, out ipAddress))
                    {
                        dataBytes = ipAddress.GetAddressBytes();
                    }
                    else if (!string.IsNullOrEmpty(data))
                    {
                        dataBytes = Encoding.UTF8.GetBytes(data);
                    }
                    break;

                case "CNAME":
                    typeBytes = new byte[] { 0x00, 0x05 };
                    if (!string.IsNullOrEmpty(data) && IPAddress.TryParse(data, out ipAddress))
                    {
                        dataBytes = NewDNSNameArray(data).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else if (!string.IsNullOrEmpty(data))
                    {
                        dataBytes = NewDNSNameArray(data.Replace("." + zone, "")).Concat(new byte[] { 0xc0, 0x0c }).ToArray();
                    }
                    break;

                case "MX":
                    typeBytes = new byte[] { 0x00, 0x0f };
                    if (!string.IsNullOrEmpty(data))
                    {
                        extraLength = 2;
                        preferenceBytes = BitConverter.GetBytes((short)preference);
                        Array.Reverse(preferenceBytes);
                    }
                    if (!string.IsNullOrEmpty(data) && IPAddress.TryParse(data, out ipAddress))
                    {
                        dataBytes = NewDNSNameArray(data).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else if (!string.IsNullOrEmpty(data))
                    {
                        dataBytes = NewDNSNameArray(data.Replace("." + zone, "")).Concat(new byte[] { 0xc0, 0x0c }).ToArray();
                    }
                    break;

                case "PTR":
                    typeBytes = new byte[] { 0x00, 0x0c };
                    if (!string.IsNullOrEmpty(data))
                    {
                        dataBytes = NewDNSNameArray(data).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    break;

                case "SRV":
                    typeBytes = new byte[] { 0x00, 0x21 };
                    if (!string.IsNullOrEmpty(data))
                    {
                        byte[] priorityBytes = BitConverter.GetBytes((short)priority);
                        Array.Reverse(priorityBytes);
                        byte[] weightBytes = BitConverter.GetBytes((short)weight);
                        Array.Reverse(weightBytes);
                        byte[] portBytes = BitConverter.GetBytes((short)port);
                        Array.Reverse(portBytes);
                        extraLength = 6;
                        dataBytes = NewDNSNameArray(data).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    break;

                case "TXT":
                    typeBytes = new byte[] { 0x00, 0x10 };
                    txtLengthBytes = BitConverter.GetBytes(data.Length).Take(1).ToArray();
                    if (!string.IsNullOrEmpty(data))
                    {
                        extraLength = 1;
                        dataBytes = Encoding.UTF8.GetBytes(data);
                    }
                    break;
            }

            byte[] nameBytes;
            if (name == zone)
            {
                nameBytes = new byte[] { 0xc0, 0x0c };
            }
            else
            {
                nameBytes = NewDNSNameArray(name.Replace("." + zone, "")).Concat(new byte[] { 0xc0, 0x0c }).ToArray();
            }

            byte[] zoneBytes = NewDNSNameArray(zone).Concat(new byte[] { 0x00 }).ToArray();
            byte[] ttlBytes = BitConverter.GetBytes(ttl).Reverse().ToArray();
            byte[] dataLengthBytes = BitConverter.GetBytes((short)(dataBytes.Length + extraLength)).Take(2).Reverse().ToArray();

            byte[] length = null;
            if (mac != null)
            {
                length = BitConverter.GetBytes((short)(zoneBytes.Length + nameBytes.Length + dataBytes.Length + tKeyname.Length + mac.Length + 62 + extraLength));
                Array.Reverse(length);
            }
            else if (tKeyname == null)
            {
                length = BitConverter.GetBytes((short)(zoneBytes.Length + nameBytes.Length + dataBytes.Length + 26 + extraLength));
                Array.Reverse(length);
            }

            OrderedDictionary dnsUpdate = new OrderedDictionary();

            if (tKeyname == null || mac != null)
            {
                dnsUpdate.Add("Length", length);
            }

            dnsUpdate.Add("TransactionID", transactionID);
            dnsUpdate.Add("Flags", new byte[] { 0x28, 0x00 });
            dnsUpdate.Add("Zones", new byte[] { 0x00, 0x01 });
            dnsUpdate.Add("Prerequisites", new byte[] { 0x00, 0x00 });
            dnsUpdate.Add("Updates", new byte[] { 0x00, 0x01 });

            if (mac != null)
            {
                dnsUpdate.Add("AdditionalRRs", new byte[] { 0x00, 0x01 });
            }
            else
            {
                dnsUpdate.Add("AdditionalRRs", new byte[] { 0x00, 0x00 });
            }

            dnsUpdate.Add("Zone_Name", zoneBytes);
            dnsUpdate.Add("Zone_Type", new byte[] { 0x00, 0x06 });
            dnsUpdate.Add("Zone_Class", new byte[] { 0x00, 0x01 });
            dnsUpdate.Add("Updates_Name", nameBytes);
            dnsUpdate.Add("Updates_Type", typeBytes);
            dnsUpdate.Add("Updates_Class", classBytes);
            dnsUpdate.Add("Updates_TTL", ttlBytes);
            dnsUpdate.Add("Updates_DataLength", dataLengthBytes);

            if (type.ToUpper() == "MX")
            {
                dnsUpdate.Add("Updates_TXTLength", preferenceBytes);
            }

            if (type.ToUpper() == "TXT" && add)
            {
                dnsUpdate.Add("Updates_TXTLength", txtLengthBytes);
            }

            if (type.ToUpper() == "SRV" && add)
            {
                dnsUpdate.Add("Updates_Priority", priority);
                dnsUpdate.Add("Updates_Weight", weight);
                dnsUpdate.Add("Updates_Port", port);
            }

            if (add)
            {
                dnsUpdate.Add("Updates_Address", dataBytes);
            }

            if (tKeyname != null)
            {
                dnsUpdate.Add("AdditionalRecords_Name", tKeyname);

                if (mac != null)
                {
                    dnsUpdate.Add("AdditionalRecords_Type", new byte[] { 0x00, 0xfa });
                }

                dnsUpdate.Add("AdditionalRecords_Class", new byte[] { 0x00, 0xff });
                dnsUpdate.Add("AdditionalRecords_TTL", new byte[] { 0x00, 0x00, 0x00, 0x00 });

                if (mac != null)
                {
                    dnsUpdate.Add("AdditionalRecords_DataLength", new byte[] { 0x00, 0x36 });
                }

                dnsUpdate.Add("AdditionalRecords_AlgorithmName", new byte[] { 0x08, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67, 0x00 });
                dnsUpdate.Add("AdditionalRecords_TimeSigned", timeSigned);
                dnsUpdate.Add("AdditionalRecords_Fudge", new byte[] { 0x01, 0x2c });

                if (mac != null)
                {
                    dnsUpdate.Add("AdditionalRecords_MACSize", new byte[] { 0x00, 0x1c });
                    dnsUpdate.Add("AdditionalRecords_MAC", mac);
                    dnsUpdate.Add("AdditionalRecords_OriginalID", transactionID);
                }

                dnsUpdate.Add("AdditionalRecords_Error", new byte[] { 0x00, 0x00 });
                dnsUpdate.Add("AdditionalRecords_OtherLength", new byte[] { 0x00, 0x00 });
            }

            return dnsUpdate;
        }

        public static OrderedDictionary NewPacketDNSUpdateMAC(byte[] flags, byte[] sequenceNumber, byte[] checksum)
        {
            OrderedDictionary dnsUpdateMAC = new OrderedDictionary();
            dnsUpdateMAC.Add("DNSUpdateMAC_TokenID", new byte[] { 0x04, 0x04 });
            dnsUpdateMAC.Add("DNSUpdateMAC_Flags", flags);
            dnsUpdateMAC.Add("DNSUpdateMAC_Filler", new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff });
            dnsUpdateMAC.Add("DNSUpdateMAC_SequenceNumber", new byte[] { 0x00, 0x00, 0x00, 0x00 }.Concat(sequenceNumber).ToArray());

            if (checksum != null && checksum.Length > 0)
            {
                dnsUpdateMAC.Add("DNSUpdateMAC_Checksum", checksum);
            }

            return dnsUpdateMAC;
        }

        public static string GetDNSUpdateResponseStatus(byte[] dnsClientReceive)
        {
            List<byte> dnsClientReceiveList = new List<byte>();
            dnsClientReceiveList.Add(dnsClientReceive[4]);
            dnsClientReceiveList.Add(dnsClientReceive[5]);

            string dnsResponseFlags = BitConverter.ToString(dnsClientReceiveList.ToArray()).Replace("-", "");

            string dnsUpdateResponseStatus;

            switch (dnsResponseFlags)
            {
                case "A800":
                    dnsUpdateResponseStatus = "[+] DNS update successful";
                    break;
                case "A801":
                    dnsUpdateResponseStatus = "[-] format error 0x" + dnsResponseFlags;
                    break;
                case "A802":
                    dnsUpdateResponseStatus = "[-] failed to complete 0x" + dnsResponseFlags;
                    break;
                case "A804":
                    dnsUpdateResponseStatus = "[-] not implemented 0x" + dnsResponseFlags;
                    break;
                case "A805":
                    dnsUpdateResponseStatus = "[-] update refused 0x" + dnsResponseFlags;
                    break;
                default:
                    dnsUpdateResponseStatus = "[-] DNS update was not successful 0x" + dnsResponseFlags;
                    break;
            }

            return dnsUpdateResponseStatus;
        }
    }
}
