
rule PWS_Win32_Yahoopass_E{
	meta:
		description = "PWS:Win32/Yahoopass.E,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 70 00 62 00 6b 00 5c 00 72 00 61 00 73 00 70 00 68 00 6f 00 6e 00 65 00 2e 00 70 00 62 00 6b 00 } //1 Microsoft\Network\Connections\pbk\rasphone.pbk
		$a_00_1 = {43 00 2a 00 5c 00 41 00 4a 00 3a 00 5c 00 59 00 61 00 6b 00 6f 00 7a 00 61 00 20 00 76 00 33 00 2e 00 35 00 5c 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //1 C*\AJ:\Yakoza v3.5\server\Server.vbp
		$a_00_2 = {4c 00 24 00 5f 00 52 00 61 00 73 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 23 00 30 00 } //1 L$_RasDefaultCredentials#0
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {59 00 61 00 68 00 6f 00 6f 00 42 00 75 00 64 00 64 00 79 00 4d 00 61 00 69 00 6e 00 } //1 YahooBuddyMain
		$a_01_7 = {43 49 45 50 61 73 73 77 6f 72 64 73 } //1 CIEPasswords
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}