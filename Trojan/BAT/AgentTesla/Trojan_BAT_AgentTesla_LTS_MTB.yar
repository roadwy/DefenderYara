
rule Trojan_BAT_AgentTesla_LTS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 5f 00 ac 00 5f 00 5f 00 71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f 00 97 00 70 00 5f 00 65 00 64 00 5f 00 5f } //01 00 
		$a_01_1 = {68 00 5f 00 a5 00 61 00 af 00 91 00 5f 00 6b 00 6a 00 5f 00 9f 00 61 00 97 00 7e 00 5f 00 5f 00 62 00 5f 00 4e } //01 00 
		$a_01_2 = {24 32 32 30 30 66 36 39 65 2d 37 36 35 35 2d 34 64 39 62 2d 61 30 64 63 2d 38 38 39 35 39 63 36 62 64 66 36 34 } //01 00  $2200f69e-7655-4d9b-a0dc-88959c6bdf64
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //00 00  DebuggerBrowsableState
	condition:
		any of ($a_*)
 
}