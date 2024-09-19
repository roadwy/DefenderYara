
rule Trojan_Win32_SuspGolang_MN{
	meta:
		description = "Trojan:Win32/SuspGolang.MN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_81_0 = {4d 69 67 72 61 74 65 29 2e } //1 Migrate).
		$a_81_1 = {49 6e 76 6f 6b 65 47 65 74 53 79 73 74 65 6d 52 65 71 29 2e } //1 InvokeGetSystemReq).
		$a_81_2 = {49 6e 76 6f 6b 65 53 70 61 77 6e 44 6c 6c 52 65 71 29 2e } //1 InvokeSpawnDllReq).
		$a_81_3 = {53 69 64 65 6c 6f 61 64 52 65 71 29 2e } //1 SideloadReq).
		$a_81_4 = {45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 65 71 29 2e } //1 ExecuteAssemblyReq).
		$a_81_5 = {49 6d 70 65 72 73 6f 6e 61 74 65 29 2e } //1 Impersonate).
		$a_81_6 = {49 6e 76 6f 6b 65 4d 69 67 72 61 74 65 52 65 71 29 2e } //1 InvokeMigrateReq).
		$a_81_7 = {29 2e 50 61 73 73 77 6f 72 64 } //1 ).Password
		$a_81_8 = {29 2e 48 6f 73 74 6e 61 6d 65 } //1 ).Hostname
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=7
 
}