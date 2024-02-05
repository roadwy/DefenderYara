
rule Trojan_BAT_Formbook_NJS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 32 30 37 62 66 33 66 38 2d 33 34 66 34 2d 34 30 38 61 2d 61 62 65 63 2d 30 61 62 63 61 33 30 36 62 36 35 61 } //01 00 
		$a_01_1 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00 
		$a_81_2 = {4b 75 6c 69 62 69 6e 67 } //01 00 
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_81_4 = {4d 61 74 69 6b 6b 61 50 65 6c 69 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}