
rule Trojan_AndroidOS_SpyBanker_M{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.M,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {4c 73 65 43 2f 76 71 64 6a 71 2f 69 75 68 6c 79 73 75 69 2f 49 65 73 6e 75 6a 49 75 68 6c 79 73 75 } //01 00 
		$a_01_1 = {63 6f 6e 73 74 5f 74 61 73 6b 5f 69 64 5f 73 65 6e 64 5f 73 6d 73 } //01 00 
		$a_01_2 = {72 65 63 65 69 76 65 72 53 74 61 74 75 73 53 6d 73 } //01 00 
		$a_01_3 = {75 70 64 20 63 6f 6e 74 61 63 74 20 6c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}