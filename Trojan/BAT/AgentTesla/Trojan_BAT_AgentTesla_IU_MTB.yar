
rule Trojan_BAT_AgentTesla_IU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 25 16 03 a2 14 14 14 28 90 01 03 0a 74 90 01 03 01 0a 02 06 72 90 01 03 70 6f 90 01 03 0a 7d 90 01 03 04 2a 90 00 } //01 00 
		$a_81_1 = {53 30 2e 45 4f } //01 00  S0.EO
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_81_4 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //01 00  ArrayAttribute
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_6 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}