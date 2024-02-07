
rule Backdoor_BAT_Draliz_A{
	meta:
		description = "Backdoor:BAT/Draliz.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 69 00 7a 00 61 00 72 00 64 00 20 00 52 00 61 00 74 00 } //01 00  Lizard Rat
		$a_01_1 = {53 74 61 72 74 55 44 50 } //01 00  StartUDP
		$a_01_2 = {53 74 6f 70 55 44 50 } //01 00  StopUDP
		$a_01_3 = {53 74 61 72 74 48 54 54 50 } //01 00  StartHTTP
		$a_01_4 = {53 74 6f 70 48 54 54 50 } //01 00  StopHTTP
		$a_01_5 = {68 74 74 70 72 75 6e } //00 00  httprun
	condition:
		any of ($a_*)
 
}