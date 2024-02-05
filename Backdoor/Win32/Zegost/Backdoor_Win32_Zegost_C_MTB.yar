
rule Backdoor_Win32_Zegost_C_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 45 f8 03 45 f4 8b 4d 08 0f be 14 01 8b 45 0c 03 45 f4 0f be 08 3b d1 } //03 00 
		$a_80_1 = {25 73 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44 } //%s\SHELL\OPEN\COMMAND  03 00 
		$a_80_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 6e 65 74 63 61 63 68 65 } //\CurrentVersion\netcache  03 00 
		$a_80_3 = {4b 76 4d 6f 6e 58 50 2e 65 78 65 } //KvMonXP.exe  03 00 
		$a_80_4 = {53 68 75 74 64 6f 77 6e 57 69 74 68 6f 75 74 4c 6f 67 6f 6e } //ShutdownWithoutLogon  03 00 
		$a_80_5 = {45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 } //EnableAdminTSRemote  03 00 
		$a_80_6 = {44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //DenyTSConnections  00 00 
	condition:
		any of ($a_*)
 
}