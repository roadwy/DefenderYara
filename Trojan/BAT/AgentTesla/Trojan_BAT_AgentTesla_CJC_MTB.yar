
rule Trojan_BAT_AgentTesla_CJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 58 58 58 58 58 58 00 53 00 57 53 53 00 } //01 00  堀塘塘XS南S
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //01 00  ArrayAttribute
		$a_01_3 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}