
rule Trojan_AndroidOS_SpyBanker_I{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.I,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 45 51 5f 43 4f 44 45 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 52 45 43 45 49 56 45 5f 53 4d 53 } //01 00 
		$a_01_1 = {4c 73 72 74 68 6b 2f 70 74 68 6b 2f 73 6d 73 66 6f 72 77 61 72 64 65 72 2f 73 65 72 76 69 63 65 73 } //01 00 
		$a_01_2 = {55 52 4c 5f 41 54 4d } //01 00 
		$a_01_3 = {52 65 63 65 69 76 65 64 20 53 4d 53 20 66 72 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}