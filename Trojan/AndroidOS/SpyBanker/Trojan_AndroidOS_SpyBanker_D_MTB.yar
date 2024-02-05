
rule Trojan_AndroidOS_SpyBanker_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 61 69 6c 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_1 = {75 70 64 61 74 65 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_01_2 = {50 68 6f 6e 65 53 74 61 74 52 65 63 65 69 76 65 72 } //01 00 
		$a_01_3 = {73 65 6e 64 43 61 6c 6c 49 6e 66 6f } //01 00 
		$a_01_4 = {73 65 6e 64 55 73 65 72 49 6e 66 6f } //01 00 
		$a_01_5 = {67 65 74 43 61 6c 6c 4e 75 6d 62 65 72 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}