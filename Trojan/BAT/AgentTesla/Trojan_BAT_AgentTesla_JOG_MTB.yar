
rule Trojan_BAT_AgentTesla_JOG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 66 38 30 65 38 37 37 33 2d 34 63 38 63 2d 34 33 35 35 2d 61 32 38 61 2d 37 38 64 34 62 33 62 66 32 32 36 38 } //01 00  $f80e8773-4c8c-4355-a28a-78d4b3bf2268
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_3 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_81_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}