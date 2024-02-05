
rule Trojan_BAT_AgentTesla_EEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 35 38 38 43 46 38 42 31 2d 36 31 35 37 2d 34 43 43 45 2d 39 42 32 36 2d 45 42 34 31 31 38 35 39 31 38 45 32 } //01 00 
		$a_01_1 = {00 53 75 62 73 74 72 69 6e 67 00 } //01 00 
		$a_01_2 = {00 54 6f 55 49 6e 74 33 32 00 } //01 00 
		$a_01_3 = {00 47 65 74 54 79 70 65 73 00 } //01 00 
		$a_01_4 = {00 47 65 74 4d 65 74 68 6f 64 73 00 } //01 00 
		$a_01_5 = {00 49 6e 76 6f 6b 65 00 } //01 00 
		$a_01_6 = {00 4d 61 74 68 00 53 71 72 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}