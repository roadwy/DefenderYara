
rule Trojan_Win32_SuspGolang_NK{
	meta:
		description = "Trojan:Win32/SuspGolang.NK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {29 2e 41 66 66 69 72 6d 4c 6f 67 69 6e } //1 ).AffirmLogin
		$a_81_1 = {29 2e 4c 6f 61 64 4f 72 53 74 6f 72 65 } //1 ).LoadOrStore
		$a_81_2 = {29 2e 47 65 74 55 73 65 72 50 72 6f 66 69 6c 65 44 69 72 65 63 74 6f 72 79 } //1 ).GetUserProfileDirectory
		$a_81_3 = {29 2e 4c 6f 61 64 41 6e 64 44 65 6c 65 74 65 } //1 ).LoadAndDelete
		$a_81_4 = {29 2e 43 6f 6d 70 61 72 65 41 6e 64 44 65 6c 65 74 65 } //1 ).CompareAndDelete
		$a_81_5 = {29 2e 54 72 79 4c 6f 63 6b } //1 ).TryLock
		$a_81_6 = {29 2e 4e 61 6e 6f 73 65 63 6f 6e 64 73 } //1 ).Nanoseconds
		$a_81_7 = {29 2e 47 65 74 54 6f 6b 65 6e 50 72 69 6d 61 72 79 47 72 6f 75 70 } //1 ).GetTokenPrimaryGroup
		$a_81_8 = {29 2e 47 65 74 54 6f 6b 65 6e 55 73 65 72 } //1 ).GetTokenUser
		$a_81_9 = {49 6e 76 6f 6b 65 49 6e 50 72 6f 63 45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 65 71 29 2e } //1 InvokeInProcExecuteAssemblyReq).
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}