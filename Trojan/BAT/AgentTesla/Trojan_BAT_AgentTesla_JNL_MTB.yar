
rule Trojan_BAT_AgentTesla_JNL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 08 00 00 32 00 "
		
	strings :
		$a_01_0 = {00 57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 00 } //0a 00  圀彟彟彟彟彟W
		$a_01_1 = {00 58 5f 58 5f 58 5f 58 5f 41 5f 41 5f 41 5f 41 5f 53 5f 53 5f 53 5f 53 00 } //0a 00 
		$a_01_2 = {00 58 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 58 00 } //01 00  堀彟彟彟彟彟X
		$a_01_3 = {67 65 74 5f 50 61 72 61 6d 58 47 72 6f 75 70 } //01 00  get_ParamXGroup
		$a_01_4 = {67 65 74 5f 50 61 72 61 6d 58 41 72 72 61 79 } //01 00  get_ParamXArray
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}