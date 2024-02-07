
rule Trojan_BAT_AgentTesla_LUP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 39 33 39 62 36 64 34 66 2d 36 61 32 66 2d 34 33 65 66 2d 38 32 66 36 2d 35 36 65 34 32 34 35 38 35 36 34 35 } //01 00  $939b6d4f-6a2f-43ef-82f6-56e424585645
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_2 = {54 00 6f 00 57 00 69 00 6e 00 33 00 32 } //01 00 
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //00 00  DebuggerBrowsableState
	condition:
		any of ($a_*)
 
}