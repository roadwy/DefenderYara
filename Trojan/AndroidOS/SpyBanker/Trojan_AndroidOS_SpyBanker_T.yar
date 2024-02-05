
rule Trojan_AndroidOS_SpyBanker_T{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.T,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 5f 39 2f 69 6e 64 65 78 5f 39 2e 70 68 70 } //02 00 
		$a_01_1 = {45 58 54 52 41 5f 53 4d 53 5f 4e 4f 5f 39 } //02 00 
		$a_01_2 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f 39 } //02 00 
		$a_01_3 = {45 58 54 52 41 5f 53 4d 53 5f 4d 45 53 53 41 47 45 5f 39 } //00 00 
	condition:
		any of ($a_*)
 
}