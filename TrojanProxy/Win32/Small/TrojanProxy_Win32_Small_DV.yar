
rule TrojanProxy_Win32_Small_DV{
	meta:
		description = "TrojanProxy:Win32/Small.DV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00  %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_01_1 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_01_3 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //01 00  EnumProcessModules
		$a_01_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_5 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //01 00  OpenProcessToken
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_7 = {55 75 69 64 43 72 65 61 74 65 } //01 00  UuidCreate
		$a_01_8 = {5c 75 73 62 70 64 61 2e 64 6c 6c } //01 00  \usbpda.dll
		$a_01_9 = {5c 75 73 62 70 64 61 75 70 2e 64 6c 6c } //00 00  \usbpdaup.dll
	condition:
		any of ($a_*)
 
}