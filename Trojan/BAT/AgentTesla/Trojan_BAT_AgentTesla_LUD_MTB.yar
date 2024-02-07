
rule Trojan_BAT_AgentTesla_LUD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 39 64 62 61 39 36 66 31 2d 33 33 66 38 2d 34 64 35 34 2d 38 36 63 66 2d 64 39 33 64 64 37 37 65 32 37 38 63 } //01 00  $9dba96f1-33f8-4d54-86cf-d93dd77e278c
		$a_01_1 = {42 43 32 33 34 32 34 32 33 34 32 } //01 00  BC234242342
		$a_01_2 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_3 = {42 43 36 35 36 32 33 34 35 32 33 35 34 32 } //01 00  BC656234523542
		$a_01_4 = {45 33 35 34 32 33 34 35 33 34 36 } //01 00  E3542345346
		$a_01_5 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}