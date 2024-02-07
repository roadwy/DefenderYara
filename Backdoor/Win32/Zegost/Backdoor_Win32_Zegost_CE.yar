
rule Backdoor_Win32_Zegost_CE{
	meta:
		description = "Backdoor:Win32/Zegost.CE,SIGNATURE_TYPE_PEHSTR,33 00 33 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 65 73 65 74 53 53 44 54 } //0a 00  ResetSSDT
		$a_01_1 = {47 68 30 73 74 20 55 70 64 61 74 65 } //0a 00  Gh0st Update
		$a_01_2 = {53 65 72 76 69 63 65 44 6c 6c } //0a 00  ServiceDll
		$a_01_3 = {25 73 5c 25 73 65 78 2e 64 6c 6c } //0a 00  %s\%sex.dll
		$a_01_4 = {6e 65 74 73 76 63 73 5f 30 78 25 64 } //0a 00  netsvcs_0x%d
		$a_01_5 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00  %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_01_6 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 } //01 00  OpenSCManager
		$a_01_7 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 43 6f 6e 74 72 6f 6c } //01 00  SetSecurityDescriptorControl
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
	condition:
		any of ($a_*)
 
}