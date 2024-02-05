
rule Trojan_Win32_Vmprotbad_AMQ_MTB{
	meta:
		description = "Trojan:Win32/Vmprotbad.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {5c 57 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //\Windows\explorer.exe  03 00 
		$a_80_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //SeDebugPrivilege  03 00 
		$a_80_2 = {78 7a 2e 64 74 33 39 39 2e 63 6e } //xz.dt399.cn  03 00 
		$a_80_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  03 00 
		$a_80_4 = {57 54 53 53 65 6e 64 4d 65 73 73 61 67 65 57 } //WTSSendMessageW  03 00 
		$a_80_5 = {57 54 53 51 75 65 72 79 55 73 65 72 54 6f 6b 65 6e } //WTSQueryUserToken  03 00 
		$a_80_6 = {47 65 74 50 72 6f 63 65 73 73 41 66 66 69 6e 69 74 79 4d 61 73 6b } //GetProcessAffinityMask  00 00 
	condition:
		any of ($a_*)
 
}