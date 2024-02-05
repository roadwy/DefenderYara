
rule Trojan_AndroidOS_SpyBanker_JK{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.JK,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 61 78 61 70 69 2e 65 61 73 65 63 61 72 65 2e 73 62 73 2f 61 70 69 } //02 00 
		$a_01_1 = {63 61 72 64 73 2f 61 78 61 70 69 2f 53 65 72 76 69 63 65 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 } //02 00 
		$a_01_2 = {41 64 68 61 72 20 63 61 72 64 20 69 73 20 72 65 71 75 69 72 65 64 20 69 73 20 72 65 71 75 69 72 65 64 } //02 00 
		$a_01_3 = {63 61 72 64 73 2f 61 78 61 70 69 2f 53 65 63 6f 6e 64 46 6f 72 6d } //00 00 
	condition:
		any of ($a_*)
 
}