
rule Trojan_BAT_AgentTesla_BVI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {20 c8 00 00 00 da 1f 64 da 1f 1e d6 20 90 01 00 00 da } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_6 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_7 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //00 00  IExpando.Plug
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BVI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {00 61 7a 78 00 43 6f 6e 74 61 69 6e 65 72 00 } //0a 00 
		$a_81_1 = {00 44 53 44 53 00 53 00 59 72 64 61 00 } //0a 00 
		$a_81_2 = {00 69 6d 69 6d 69 6d 69 6d 69 6d 00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //01 00 
		$a_81_3 = {4f 62 73 6f 6c 65 74 65 41 74 74 72 69 62 75 74 65 } //01 00  ObsoleteAttribute
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}