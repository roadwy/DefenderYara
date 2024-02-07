
rule Trojan_BAT_Lokibot_EE_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0c 00 00 14 00 "
		
	strings :
		$a_00_0 = {24 31 66 61 35 38 65 64 37 2d 66 61 34 62 2d 34 66 33 32 2d 61 66 32 38 2d 32 39 32 66 63 33 36 61 33 65 31 35 } //14 00  $1fa58ed7-fa4b-4f32-af28-292fc36a3e15
		$a_00_1 = {24 66 35 34 32 64 62 39 36 2d 36 38 64 32 2d 34 33 37 63 2d 61 33 62 32 2d 30 30 62 62 63 65 63 65 38 35 61 65 } //01 00  $f542db96-68d2-437c-a3b2-00bbcece85ae
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_10 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_11 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}