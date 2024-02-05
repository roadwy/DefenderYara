
rule Trojan_AndroidOS_SpyBanker_D{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 73 61 76 65 5f 73 6d 73 } //02 00 
		$a_01_1 = {53 31 6d 32 73 33 52 34 65 35 63 36 65 37 69 38 76 39 65 30 72 } //02 00 
		$a_01_2 = {43 31 6f 32 6e 33 73 34 74 35 61 36 6e 37 74 38 73 39 } //00 00 
	condition:
		any of ($a_*)
 
}