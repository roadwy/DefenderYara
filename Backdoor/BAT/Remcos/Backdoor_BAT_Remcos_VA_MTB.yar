
rule Backdoor_BAT_Remcos_VA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {72 65 6d 6f 76 65 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 remove_LinkClicked
		$a_81_1 = {6c 6c 5f 53 65 61 72 63 68 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_Search_LinkClicked
		$a_81_2 = {6c 6c 5f 45 6d 61 69 6c 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_Email_LinkClicked
		$a_81_3 = {6c 6c 5f 43 61 6c 63 75 6c 61 74 6f 72 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_Calculator_LinkClicked
		$a_81_4 = {6c 6c 5f 41 64 64 52 65 63 6f 72 64 73 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_AddRecords_LinkClicked
		$a_81_5 = {6c 6c 5f 50 72 69 6e 74 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_Print_LinkClicked
		$a_81_6 = {6c 6c 5f 45 78 70 6f 72 74 5f 4c 69 6e 6b 43 6c 69 63 6b 65 64 } //1 ll_Export_LinkClicked
		$a_81_7 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_8 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_10 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_11 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
		$a_81_12 = {67 65 74 5f 4b 65 79 43 68 61 72 } //1 get_KeyChar
		$a_81_13 = {67 65 74 5f 44 61 74 61 4d 65 6d 62 65 72 } //1 get_DataMember
		$a_81_14 = {4f 6c 65 44 62 44 61 74 61 52 65 61 64 65 72 } //1 OleDbDataReader
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}