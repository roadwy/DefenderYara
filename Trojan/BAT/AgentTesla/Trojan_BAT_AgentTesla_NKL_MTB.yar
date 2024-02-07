
rule Trojan_BAT_AgentTesla_NKL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 32 65 39 35 66 38 33 36 2d 34 36 65 64 2d 34 34 32 39 2d 61 66 38 32 2d 38 39 62 35 37 63 30 32 36 34 34 62 } //01 00  $2e95f836-46ed-4429-af82-89b57c02644b
		$a_80_1 = {72 6e 62 71 6b 62 6e 72 2f 70 70 70 70 70 70 70 70 2f 38 2f 38 2f 38 2f 38 2f 50 50 50 50 50 50 50 50 2f 52 4e 42 51 4b 42 4e 52 20 77 20 4b 51 6b 71 20 2d 20 30 20 31 } //rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1  01 00 
		$a_01_2 = {54 61 75 72 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Taurus.Properties.Resources.resources
		$a_01_3 = {57 61 63 63 61 6d 61 77 27 73 20 48 6f 6d 65 70 6c 61 63 65 } //01 00  Waccamaw's Homeplace
		$a_01_4 = {50 72 69 76 61 74 65 20 48 6f 75 73 65 68 6f 6c 64 } //01 00  Private Household
		$a_01_5 = {32 30 31 34 20 41 75 64 69 20 52 53 20 37 } //01 00  2014 Audi RS 7
		$a_01_6 = {50 00 72 00 6f 00 6d 00 6f 00 74 00 69 00 6f 00 6e 00 20 00 74 00 79 00 70 00 65 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 64 00 65 00 66 00 69 00 6e } //01 00 
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}