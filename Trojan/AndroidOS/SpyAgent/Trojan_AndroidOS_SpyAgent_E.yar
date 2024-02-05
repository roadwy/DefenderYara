
rule Trojan_AndroidOS_SpyAgent_E{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.E,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 70 5f 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d 3d } //02 00 
		$a_01_1 = {4c 63 6f 6d 2f 64 6f 61 69 2f 64 69 61 77 2f 53 74 75 6e 6e 69 6e 67 3b } //02 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 33 38 2e 36 34 2e 39 32 2e 39 38 3a 38 39 38 39 } //00 00 
	condition:
		any of ($a_*)
 
}