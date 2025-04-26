
rule Virus_Win32_Autorun_B{
	meta:
		description = "Virus:Win32/Autorun.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {62 63 6c 6f 67 73 76 72 2e 69 6e 69 } //1 bclogsvr.ini
		$a_00_1 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 Windows NT\CurrentVersion\Winlogon
		$a_00_2 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 Windows\CurrentVersion\policies\Explorer\Run
		$a_00_3 = {66 6c 61 73 68 2e 62 70 61 2e 6e 75 } //1 flash.bpa.nu
		$a_00_4 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_00_5 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 69 6e 64 65 78 2e 63 67 69 } //1 http://%s:%d/index.cgi
		$a_01_6 = {47 00 65 00 6e 00 65 00 72 00 69 00 63 00 20 00 48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //1 Generic Host Process for Win32 Services
		$a_01_7 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //1 GetLogicalDriveStringsA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}