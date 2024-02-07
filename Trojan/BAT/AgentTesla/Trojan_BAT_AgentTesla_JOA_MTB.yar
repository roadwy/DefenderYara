
rule Trojan_BAT_AgentTesla_JOA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {38 61 33 66 34 63 61 62 2d 37 34 62 65 2d 34 35 35 33 2d 62 36 63 38 2d 63 36 36 37 32 65 38 31 35 34 32 30 } //01 00  8a3f4cab-74be-4553-b6c8-c6672e815420
		$a_81_1 = {41 41 41 31 32 33 } //01 00  AAA123
		$a_81_2 = {00 4f 4f 4f 4f 4f 00 } //01 00 
		$a_81_3 = {41 32 33 35 34 38 } //01 00  A23548
		$a_81_4 = {41 36 35 34 36 } //01 00  A6546
		$a_81_5 = {41 36 38 37 39 } //01 00  A6879
		$a_81_6 = {41 39 32 38 33 } //01 00  A9283
		$a_81_7 = {4b 70 33 34 } //00 00  Kp34
	condition:
		any of ($a_*)
 
}