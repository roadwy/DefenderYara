
rule Trojan_AndroidOS_SpyBanker_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 69 70 65 64 61 74 61 } //01 00 
		$a_01_1 = {66 61 6b 65 70 69 6e 5f 61 63 74 69 76 69 74 79 } //01 00 
		$a_00_2 = {63 72 65 61 74 65 73 63 72 65 65 6e 63 61 70 74 75 72 65 69 6e 74 65 6e 74 } //01 00 
		$a_01_3 = {63 6f 6e 74 61 63 74 73 75 74 69 6c 73 } //01 00 
		$a_00_4 = {73 6d 73 70 75 73 68 5f 62 72 } //01 00 
		$a_00_5 = {63 72 65 64 65 6e 74 69 61 6c 73 2e 6a 61 76 61 } //00 00 
	condition:
		any of ($a_*)
 
}