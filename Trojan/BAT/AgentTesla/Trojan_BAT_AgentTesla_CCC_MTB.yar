
rule Trojan_BAT_AgentTesla_CCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //01 00  IExpando.Plug
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {43 6f 6e 74 72 6f 6c 65 50 6f 72 54 77 69 74 74 65 72 } //01 00  ControlePorTwitter
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_6 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_7 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_8 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}