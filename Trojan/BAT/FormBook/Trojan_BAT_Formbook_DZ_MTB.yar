
rule Trojan_BAT_Formbook_DZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0e 00 00 "
		
	strings :
		$a_81_0 = {24 39 39 35 35 39 37 63 37 2d 65 30 37 64 2d 34 30 64 61 2d 39 63 65 61 2d 37 32 61 37 34 37 36 33 30 33 66 64 } //10 $995597c7-e07d-40da-9cea-72a7476303fd
		$a_81_1 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //1 GetResourceString
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {67 65 74 5f 47 65 74 49 6e 73 74 61 6e 63 65 } //1 get_GetInstance
		$a_81_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_8 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //1 get_Computer
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_10 = {42 61 74 74 6c 65 74 65 63 68 2e 52 65 73 6f 75 72 63 65 73 } //1 Battletech.Resources
		$a_81_11 = {50 69 6c 6f 74 20 50 69 6c 6f 74 69 6e 67 } //1 Pilot Piloting
		$a_81_12 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_13 = {53 70 6c 61 73 68 53 63 72 65 65 6e 31 } //1 SplashScreen1
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=20
 
}