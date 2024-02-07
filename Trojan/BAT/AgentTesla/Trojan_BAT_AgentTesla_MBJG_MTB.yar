
rule Trojan_BAT_AgentTesla_MBJG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 3a 00 41 00 44 00 3a 00 3a 00 41 00 5f 00 3a 00 3a 00 41 00 50 00 37 00 37 00 59 00 3a 00 43 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 41 00 43 00 3a 00 3a 00 3a 00 } //01 00  JVNJ:AD::A_::AP77Y:C4:::::AC:::
		$a_01_1 = {41 00 51 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 41 00 5f 00 51 00 47 00 34 00 3a 00 41 00 4a 00 34 00 3a 00 3a 00 3a 00 51 00 3a 00 3a 00 34 00 41 00 44 00 3a 00 3a 00 3a 00 } //01 00  AQ::::::::A_QG4:AJ4:::Q::4AD:::
		$a_01_2 = {20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 } //00 00   Lo-ad 
	condition:
		any of ($a_*)
 
}