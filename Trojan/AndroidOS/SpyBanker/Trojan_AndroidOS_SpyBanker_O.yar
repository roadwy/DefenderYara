
rule Trojan_AndroidOS_SpyBanker_O{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6e 74 2d 65 2d 61 70 70 6c 79 2d 63 61 6d 70 61 69 67 6e 2d 70 61 67 65 2d 69 64 66 2d 63 61 6d 70 61 69 67 6e 2d 66 69 78 2e 78 79 7a } //02 00 
		$a_01_1 = {62 66 68 66 68 66 72 6f 6d } //02 00 
		$a_01_2 = {53 6d 73 57 6f 72 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}