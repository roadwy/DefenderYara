
rule Trojan_BAT_Bladabindi_JNGM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.JNGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_81_0 = {4d 64 35 44 65 63 72 79 70 74 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_2 = {47 65 74 42 79 74 65 73 } //02 00 
		$a_81_3 = {52 53 4d 44 5f 45 43 } //01 00 
		$a_01_4 = {00 44 65 63 5f 74 00 } //01 00 
		$a_01_5 = {00 72 61 6a 61 77 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}