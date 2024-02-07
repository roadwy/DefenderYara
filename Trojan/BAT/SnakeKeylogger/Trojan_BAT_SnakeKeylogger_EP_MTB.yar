
rule Trojan_BAT_SnakeKeylogger_EP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 14 00 "
		
	strings :
		$a_00_0 = {24 63 38 39 37 31 63 39 64 2d 36 39 30 38 2d 34 35 65 35 2d 61 65 32 64 2d 65 32 62 65 66 65 30 63 35 30 66 32 } //14 00  $c8971c9d-6908-45e5-ae2d-e2befe0c50f2
		$a_00_1 = {24 34 33 39 64 66 62 65 36 2d 66 65 63 37 2d 34 37 37 35 2d 61 37 61 32 2d 63 64 32 35 34 36 38 39 39 30 37 34 } //14 00  $439dfbe6-fec7-4775-a7a2-cd2546899074
		$a_00_2 = {24 65 30 39 32 62 36 38 37 2d 36 38 33 35 2d 34 39 32 37 2d 62 61 65 34 2d 35 34 32 32 62 31 33 66 36 35 33 36 } //01 00  $e092b687-6835-4927-bae4-5422b13f6536
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}