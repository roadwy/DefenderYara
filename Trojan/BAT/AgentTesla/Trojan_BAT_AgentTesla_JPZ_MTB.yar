
rule Trojan_BAT_AgentTesla_JPZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 07 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 07 6f 90 01 03 0a 18 5b fe 04 13 05 11 05 2d c6 90 00 } //0a 00 
		$a_01_1 = {24 38 35 36 63 36 37 36 38 2d 34 61 33 38 2d 34 38 34 36 2d 38 66 62 34 2d 39 34 65 31 62 65 63 65 65 31 64 38 } //01 00  $856c6768-4a38-4846-8fb4-94e1becee1d8
		$a_81_2 = {43 6f 6e 73 6f 6c 65 47 61 6d 65 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00  ConsoleGameCollection
		$a_81_3 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}