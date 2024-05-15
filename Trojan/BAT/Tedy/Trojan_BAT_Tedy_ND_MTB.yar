
rule Trojan_BAT_Tedy_ND_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Tedy_ND_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f c3 00 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 08 90 00 } //01 00 
		$a_01_1 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //01 00  add_ResourceResolve
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_3 = {77 00 69 00 66 00 69 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  wifi.Properties.Resources
	condition:
		any of ($a_*)
 
}