
rule Trojan_Win32_AgentTesla_RTH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 65 72 69 61 6c 69 7a 61 74 69 6f 6e 49 6e 66 6f } //1 SerializationInfo
		$a_81_1 = {67 65 74 5f 48 69 64 65 42 61 63 6b } //1 get_HideBack
		$a_81_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_5 = {4c 61 6d 64 61 58 2e 48 79 61 74 74 2e 72 65 73 6f 75 72 63 65 73 } //1 LamdaX.Hyatt.resources
		$a_81_6 = {67 65 74 5f 50 44 41 55 73 65 72 4e 61 6d 65 } //1 get_PDAUserName
		$a_81_7 = {67 65 74 5f 50 44 41 50 61 73 73 77 6f 72 64 } //1 get_PDAPassword
		$a_81_8 = {67 65 74 5f 50 44 41 44 61 74 61 54 61 62 6c 65 4e 61 6d 65 } //1 get_PDADataTableName
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}