
rule Trojan_AndroidOS_SpyAgent_C{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 6c 61 74 65 5f 70 68 69 73 68 69 6e 67 5f 75 72 6c } //01 00 
		$a_01_1 = {70 68 69 73 68 69 6e 67 5f 61 70 70 6e 61 6d 65 } //01 00 
		$a_01_2 = {73 6d 73 6c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}