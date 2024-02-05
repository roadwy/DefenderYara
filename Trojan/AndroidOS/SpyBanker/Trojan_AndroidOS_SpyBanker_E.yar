
rule Trojan_AndroidOS_SpyBanker_E{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.E,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 52 65 61 64 41 6e 64 52 65 63 65 69 76 65 41 6e 64 53 65 6e 64 53 6d 73 } //01 00 
		$a_01_1 = {63 68 65 63 6b 43 61 70 74 75 72 65 4d 69 63 } //01 00 
		$a_01_2 = {69 6e 73 70 65 63 74 6f 72 50 72 65 66 73 } //01 00 
		$a_01_3 = {63 68 65 63 6b 43 61 70 74 75 72 65 43 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}