
rule Trojan_BAT_AgentTesla_IV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_1 = {41 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 32 33 } //01 00  AZZZZZZZZZZZZZZZZ23
		$a_81_2 = {48 65 78 32 53 74 72 69 6e 67 } //01 00  Hex2String
		$a_81_3 = {00 58 44 41 53 58 41 58 41 58 00 } //01 00 
		$a_81_4 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00 } //01 00 
		$a_81_5 = {52 65 66 6c 65 63 74 69 6f 6e } //01 00  Reflection
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_7 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_8 = {53 70 6c 69 74 } //01 00  Split
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_13 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}