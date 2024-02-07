
rule VirTool_Win32_Sliver_E_MTB{
	meta:
		description = "VirTool:Win32/Sliver.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 65 71 29 2e } //01 00  ExecuteAssemblyReq).
		$a_81_1 = {49 6d 70 65 72 73 6f 6e 61 74 65 29 2e } //01 00  Impersonate).
		$a_81_2 = {49 6e 76 6f 6b 65 4d 69 67 72 61 74 65 52 65 71 29 2e } //01 00  InvokeMigrateReq).
		$a_81_3 = {44 4e 53 50 6f 6c 6c 29 2e } //01 00  DNSPoll).
		$a_81_4 = {44 4e 53 42 6c 6f 63 6b 48 65 61 64 65 72 29 2e } //01 00  DNSBlockHeader).
		$a_81_5 = {4d 69 67 72 61 74 65 29 2e } //01 00  Migrate).
		$a_81_6 = {49 6e 76 6f 6b 65 47 65 74 53 79 73 74 65 6d 52 65 71 29 2e } //01 00  InvokeGetSystemReq).
		$a_81_7 = {49 6e 76 6f 6b 65 53 70 61 77 6e 44 6c 6c 52 65 71 29 2e } //01 00  InvokeSpawnDllReq).
		$a_81_8 = {53 69 64 65 6c 6f 61 64 52 65 71 29 2e } //00 00  SideloadReq).
	condition:
		any of ($a_*)
 
}