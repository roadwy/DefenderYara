
rule Trojan_BAT_Burkina_A_MTB{
	meta:
		description = "Trojan:BAT/Burkina.A!MTB,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 41 41 41 34 41 67 76 59 43 } //0a 00 
		$a_01_1 = {41 45 41 41 41 41 41 41 41 49 73 34 48 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}