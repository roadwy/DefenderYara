
rule Trojan_BAT_njRat_MBCQ_MTB{
	meta:
		description = "Trojan:BAT/njRat.MBCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 77 00 51 00 41 00 51 00 77 00 46 00 54 00 41 00 4a 00 41 00 50 00 42 00 41 00 41 00 45 00 67 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 7a 00 } //01 00 
		$a_01_1 = {67 00 30 00 44 00 41 00 45 00 4d 00 42 00 44 00 51 00 41 00 63 00 44 00 67 00 4d 00 41 00 51 00 77 00 45 00 50 00 41 00 46 00 63 00 4f 00 41 00 77 00 41 00 } //01 00 
		$a_01_2 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //01 00 
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_4 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}