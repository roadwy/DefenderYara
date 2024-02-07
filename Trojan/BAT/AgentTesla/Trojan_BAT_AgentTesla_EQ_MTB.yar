
rule Trojan_BAT_AgentTesla_EQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {16 0d 04 17 da 13 04 16 0b 2b 0a 09 03 07 94 d6 0d 07 17 d6 0b 07 11 04 31 f1 09 6c 04 6c 5b 0c 02 02 7b 90 01 03 04 6f 90 01 03 0a 1f 0a 9a 7d 90 01 03 04 08 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 65 65 64 37 35 36 32 38 2d 32 65 61 30 2d 34 34 35 31 2d 38 63 61 34 2d 62 62 36 35 31 61 31 33 63 64 64 62 } //05 00  $eed75628-2ea0-4451-8ca4-bb651a13cddb
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //05 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {57 69 6e 43 6f 6e 74 72 6f 6c 73 2e 4c 69 73 74 56 69 65 77 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WinControls.ListView.Resources.resources
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}