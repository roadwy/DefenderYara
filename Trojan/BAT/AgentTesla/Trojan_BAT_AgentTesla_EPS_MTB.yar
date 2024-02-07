
rule Trojan_BAT_AgentTesla_EPS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 32 00 44 00 59 00 34 00 35 00 46 00 46 00 35 00 34 00 53 00 45 00 59 00 38 00 51 00 4b 00 59 00 47 00 42 00 41 00 35 00 52 00 } //01 00  12DY45FF54SEY8QKYGBA5R
		$a_01_1 = {45 00 6e 00 76 00 6f 00 69 00 } //01 00  Envoi
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}