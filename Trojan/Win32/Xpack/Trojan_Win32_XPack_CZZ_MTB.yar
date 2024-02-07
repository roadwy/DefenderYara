
rule Trojan_Win32_XPack_CZZ_MTB{
	meta:
		description = "Trojan:Win32/XPack.CZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 44 1e 04 8b d6 2b 55 f4 89 75 f4 83 f2 90 01 01 3c 90 01 01 74 90 00 } //01 00 
		$a_81_1 = {4e 45 4f 78 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00  NEOxGetProcAddress
		$a_81_2 = {56 69 72 74 75 61 6c 46 72 65 65 } //01 00  VirtualFree
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}