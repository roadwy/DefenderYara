
rule Trojan_AndroidOS_Asacub_E{
	meta:
		description = "Trojan:AndroidOS/Asacub.E,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {62 74 66 65 2e 76 74 72 67 78 2e 67 6c 62 6d } //03 00 
		$a_01_1 = {65 6e 74 72 79 50 6f 69 6e 74 24 41 75 74 6f 53 65 72 76 69 63 65 } //03 00 
		$a_01_2 = {61 6b 78 6c 2e 70 79 63 74 6c 2e 67 61 6c 64 } //00 00 
	condition:
		any of ($a_*)
 
}