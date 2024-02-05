
rule Trojan_Win32_ClipBanker_RPB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6c 69 70 70 65 72 } //01 00 
		$a_01_1 = {2f 43 72 65 61 74 65 20 2f 74 6e 20 4d 69 63 72 6f 73 6f 66 74 44 72 69 76 65 72 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 74 72 } //01 00 
		$a_01_2 = {63 61 72 64 2e 70 68 70 } //01 00 
		$a_01_3 = {75 73 65 72 6e 61 6d 65 } //01 00 
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 } //00 00 
	condition:
		any of ($a_*)
 
}