
rule Trojan_BAT_Bladabindi_EWL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 30 59 c5 7e 30 35 00 35 00 69 97 38 00 69 97 69 97 38 00 7e 30 38 00 7e 30 36 00 7e 30 37 00 7e 30 45 c5 7e 30 33 00 7e 30 35 00 35 00 69 97 38 00 } //01 00 
		$a_01_1 = {c5 69 97 38 00 7e 30 59 c5 7e 30 44 c5 7e 30 37 00 7e 30 7e 30 69 97 59 c5 7e 30 4c c5 69 97 35 00 35 00 69 97 69 97 35 00 33 00 32 00 69 97 } //00 00 
	condition:
		any of ($a_*)
 
}