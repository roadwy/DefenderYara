
rule Trojan_BAT_Formbook_DW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 10 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 33 30 64 34 61 61 33 61 2d 61 66 62 36 2d 34 37 36 35 2d 62 61 31 38 2d 66 32 33 36 34 34 37 30 65 33 34 66 } //0a 00  $30d4aa3a-afb6-4765-ba18-f2364470e34f
		$a_81_1 = {24 31 65 65 66 35 66 37 36 2d 36 32 66 32 2d 34 38 32 30 2d 39 33 34 63 2d 39 31 37 38 31 66 35 31 65 65 38 36 } //0a 00  $1eef5f76-62f2-4820-934c-91781f51ee86
		$a_81_2 = {24 66 35 64 61 37 38 62 32 2d 37 62 31 34 2d 34 38 32 34 2d 39 33 38 39 2d 30 30 61 38 37 65 37 32 64 62 34 63 } //01 00  $f5da78b2-7b14-4824-9389-00a87e72db4c
		$a_81_3 = {56 42 5f 62 6c 61 63 6b 6a 61 63 6b 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  VB_blackjack.My.Resources
		$a_81_4 = {67 61 6d 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  game.My.Resources
		$a_81_5 = {54 61 71 75 69 6e 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Taquin.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_10 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_12 = {67 65 74 5f 47 65 74 49 6e 73 74 61 6e 63 65 } //01 00  get_GetInstance
		$a_81_13 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_14 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //01 00  get_Computer
		$a_81_15 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerHiddenAttribute
	condition:
		any of ($a_*)
 
}