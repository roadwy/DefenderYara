
rule Trojan_BAT_Formbook_RDL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 37 64 36 30 63 32 66 2d 63 36 62 61 2d 34 35 36 37 2d 62 66 38 31 2d 63 35 63 30 35 32 39 37 34 31 32 66 } //01 00 
		$a_01_1 = {50 72 6f 64 75 63 65 72 49 6e 76 6f 63 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00 
		$a_01_2 = {54 4a 4d 77 64 } //01 00 
		$a_01_3 = {54 6d 61 76 77 74 79 68 65 69 7a } //00 00 
	condition:
		any of ($a_*)
 
}