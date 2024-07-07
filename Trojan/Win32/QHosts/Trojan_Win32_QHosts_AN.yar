
rule Trojan_Win32_QHosts_AN{
	meta:
		description = "Trojan:Win32/QHosts.AN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 22 63 3a 5c 41 64 6f 62 65 55 70 64 61 74 65 2e 6c 6e 6b 22 29 } //1 .CreateShortcut("c:\AdobeUpdate.lnk")
		$a_01_1 = {5c 65 74 63 5c 68 6f 73 74 73 22 22 20 2f 59 20 26 26 20 61 74 74 72 69 62 20 2b 48 } //1 \etc\hosts"" /Y && attrib +H
		$a_01_2 = {2f 6a 73 2f 64 61 74 61 2f 6a 73 2e 64 6c 6c } //1 /js/data/js.dll
		$a_01_3 = {5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 22 20 2f 76 20 22 53 63 61 6e 63 6f 64 65 20 4d 61 70 22 } //1 \Keyboard Layout" /v "Scancode Map"
		$a_01_4 = {4e 45 54 20 53 54 4f 50 20 77 73 63 73 76 63 20 26 26 20 4e 45 54 20 53 54 4f 50 20 73 68 61 72 65 64 61 63 63 65 73 73 } //1 NET STOP wscsvc && NET STOP sharedaccess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}