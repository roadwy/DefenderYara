
rule Trojan_BAT_AgentTesla_NRM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 38 62 32 35 63 36 32 2d 34 30 38 61 2d 34 64 65 34 2d 38 65 63 36 2d 37 34 31 39 65 30 38 33 65 64 39 33 } //01 00  08b25c62-408a-4de4-8ec6-7419e083ed93
		$a_01_1 = {76 62 53 74 72 69 70 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  vbStripe.Resources.resources
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}