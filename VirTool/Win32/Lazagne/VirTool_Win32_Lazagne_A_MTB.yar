
rule VirTool_Win32_Lazagne_A_MTB{
	meta:
		description = "VirTool:Win32/Lazagne.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 77 69 6e 64 6f 77 73 2e 63 72 65 64 64 75 6d 70 37 2e 77 69 6e 33 32 2e 68 61 73 68 64 75 6d 70 } //01 00  .windows.creddump7.win32.hashdump
		$a_81_1 = {2e 77 69 6e 64 6f 77 73 2e 63 72 65 64 64 75 6d 70 37 2e 77 69 6e 33 32 2e 6c 73 61 73 65 63 72 65 74 73 } //01 00  .windows.creddump7.win32.lsasecrets
		$a_81_2 = {2e 63 6f 6e 66 69 67 2e 65 78 65 63 75 74 65 5f 63 6d 64 } //01 00  .config.execute_cmd
		$a_81_3 = {2e 63 6f 6e 66 69 67 2e 44 50 41 50 49 2e 76 61 75 6c 74 } //01 00  .config.DPAPI.vault
		$a_81_4 = {2e 63 6f 6e 66 69 67 2e 44 50 41 50 49 2e 63 72 65 64 66 69 6c 65 } //01 00  .config.DPAPI.credfile
		$a_81_5 = {2e 73 6f 66 74 77 61 72 65 73 2e 77 69 6e 64 6f 77 73 2e 6c 73 61 5f 73 65 63 72 65 74 73 } //00 00  .softwares.windows.lsa_secrets
	condition:
		any of ($a_*)
 
}