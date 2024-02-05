
rule Trojan_BAT_AgentTesla_ML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {13 04 11 04 14 17 8d 90 01 02 00 01 25 16 19 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 a2 6f 90 01 02 00 0a 26 1f 17 8c 90 01 02 00 01 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ML_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 16 73 23 00 00 0a 73 24 00 00 0a 0c 00 08 90 0a 25 00 28 90 01 03 06 73 21 00 00 0a 0a 00 73 22 00 00 0a 0b 90 02 13 07 6f 25 00 00 0a 00 07 6f 26 00 00 0a 0d de 90 01 01 08 2c 07 08 6f 90 01 03 0a 00 dc 07 2c 07 07 6f 90 01 03 0a 00 dc 06 2c 07 06 6f 90 01 03 0a 00 dc 09 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00 
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00 
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_5 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}