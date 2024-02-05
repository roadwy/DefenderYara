
rule Trojan_AndroidOS_SpyAgent_P{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.P,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 70 70 4b 65 79 6c 6f 67 } //02 00 
		$a_01_1 = {44 65 76 69 63 65 49 6e 66 6f 73 2f 75 70 4e 6f 64 65 } //02 00 
		$a_01_2 = {2f 72 65 61 64 6d 65 5f 6e 6f 77 2e 74 78 74 } //02 00 
		$a_01_3 = {63 6c 65 61 72 41 70 70 4b 65 79 6c 6f 67 } //02 00 
		$a_01_4 = {67 65 74 53 4d 53 41 6c 6c 4c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}