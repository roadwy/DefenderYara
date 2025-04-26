
rule VirTool_Win32_Sliver_D_MTB{
	meta:
		description = "VirTool:Win32/Sliver.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 65 71 29 2e } //1 ExecuteAssemblyReq).
		$a_81_1 = {49 6d 70 65 72 73 6f 6e 61 74 65 29 2e } //1 Impersonate).
		$a_81_2 = {49 6e 76 6f 6b 65 4d 69 67 72 61 74 65 52 65 71 29 2e } //1 InvokeMigrateReq).
		$a_81_3 = {44 4e 53 50 6f 6c 6c 29 2e } //1 DNSPoll).
		$a_81_4 = {44 4e 53 42 6c 6f 63 6b 48 65 61 64 65 72 29 2e } //1 DNSBlockHeader).
		$a_81_5 = {29 2e 55 73 65 72 6e 61 6d 65 } //1 ).Username
		$a_81_6 = {29 2e 50 61 73 73 77 6f 72 64 } //1 ).Password
		$a_81_7 = {29 2e 48 6f 73 74 6e 61 6d 65 } //1 ).Hostname
		$a_81_8 = {29 2e 50 6f 72 74 } //1 ).Port
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}