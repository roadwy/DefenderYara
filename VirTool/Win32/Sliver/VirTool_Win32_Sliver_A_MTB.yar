
rule VirTool_Win32_Sliver_A_MTB{
	meta:
		description = "VirTool:Win32/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 6c 69 76 65 72 70 62 2e 52 65 67 69 73 74 65 72 2e 41 63 74 69 76 65 43 32 } //01 00  sliverpb.Register.ActiveC2
		$a_81_1 = {73 6c 69 76 65 72 70 62 2e 4b 69 6c 6c 53 65 73 73 69 6f 6e 52 65 71 } //01 00  sliverpb.KillSessionReq
		$a_81_2 = {73 6c 69 76 65 72 70 62 2e 52 65 67 69 73 74 65 72 2e 50 69 64 50 69 64 } //01 00  sliverpb.Register.PidPid
		$a_81_3 = {73 6c 69 76 65 72 70 62 2e 49 66 63 6f 6e 66 69 67 52 65 71 } //01 00  sliverpb.IfconfigReq
		$a_81_4 = {73 6c 69 76 65 72 70 62 2e 54 65 72 6d 69 6e 61 74 65 52 65 71 } //01 00  sliverpb.TerminateReq
		$a_81_5 = {73 6c 69 76 65 72 70 62 2e 4e 65 74 49 6e 74 65 72 66 61 63 65 73 } //00 00  sliverpb.NetInterfaces
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Sliver_A_MTB_2{
	meta:
		description = "VirTool:Win32/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 78 63 2f 6c 6f 61 64 2e 67 6f } //01 00  /xc/load.go
		$a_81_1 = {6d 61 69 6e 2e 62 61 6b 65 } //01 00  main.bake
		$a_81_2 = {73 79 73 63 61 6c 6c 2f 7a 73 79 73 63 61 6c 6c 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00  syscall/zsyscall_windows.go
		$a_03_3 = {48 89 6c 24 30 48 8d 90 01 03 48 8b 44 24 48 48 89 04 24 48 8b 44 24 40 48 89 44 24 08 e8 90 01 04 48 8b 90 01 05 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 40 48 89 44 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 90 01 04 48 8b 44 24 28 48 89 44 24 50 48 8b 6c 24 30 48 83 c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Sliver_A_MTB_3{
	meta:
		description = "VirTool:Win32/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 6c 69 76 65 72 70 62 2e 4e 65 74 49 6e 74 65 72 66 61 63 65 } //01 00  sliverpb.NetInterface
		$a_81_1 = {73 6c 69 76 65 72 70 62 2e 57 47 53 6f 63 6b 73 53 65 72 76 65 72 } //01 00  sliverpb.WGSocksServer
		$a_81_2 = {73 6c 69 76 65 72 70 62 2e 50 6f 72 74 66 77 64 50 72 6f 74 6f 63 6f 6c } //01 00  sliverpb.PortfwdProtocol
		$a_81_3 = {73 6c 69 76 65 72 70 62 2e 57 47 54 43 50 46 6f 72 77 61 72 64 65 72 } //01 00  sliverpb.WGTCPForwarder
		$a_81_4 = {2e 73 6c 69 76 65 72 70 62 2e 52 65 67 69 73 74 72 79 54 79 70 65 } //01 00  .sliverpb.RegistryType
		$a_81_5 = {2e 73 6c 69 76 65 72 70 62 2e 57 69 6e 64 6f 77 73 50 72 69 76 69 6c 65 67 65 45 6e 74 72 79 52 } //00 00  .sliverpb.WindowsPrivilegeEntryR
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Sliver_A_MTB_4{
	meta:
		description = "VirTool:Win32/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {2a 73 6c 69 76 65 72 70 62 2e 50 72 6f 63 65 73 73 } //01 00  *sliverpb.Process
		$a_03_1 = {2a 73 6c 69 76 65 72 70 62 2e 90 02 20 49 6e 66 6f 90 00 } //01 00 
		$a_81_2 = {2a 73 6c 69 76 65 72 70 62 2e 4d 69 67 72 61 74 65 } //01 00  *sliverpb.Migrate
		$a_81_3 = {2a 73 6c 69 76 65 72 70 62 2e 45 6c 65 76 61 74 65 } //01 00  *sliverpb.Elevate
		$a_03_4 = {2a 73 6c 69 76 65 72 70 62 2e 4b 69 6c 6c 90 02 20 52 65 71 90 00 } //01 00 
		$a_81_5 = {2a 73 6c 69 76 65 72 70 62 2e 44 4e 53 50 6f 6c 6c } //01 00  *sliverpb.DNSPoll
		$a_81_6 = {2a 73 6c 69 76 65 72 70 62 2e 44 4e 53 42 6c 6f 63 6b 48 65 61 64 65 72 } //01 00  *sliverpb.DNSBlockHeader
		$a_81_7 = {2a 73 6c 69 76 65 72 70 62 2e 45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 52 65 71 } //01 00  *sliverpb.ExecuteAssemblyReq
		$a_81_8 = {2a 73 6c 69 76 65 72 70 62 2e 49 6d 70 65 72 73 6f 6e 61 74 65 52 65 71 } //00 00  *sliverpb.ImpersonateReq
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Sliver_A_MTB_5{
	meta:
		description = "VirTool:Win32/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 2e 47 65 74 50 69 64 90 02 1e 29 2e 47 65 74 46 69 6c 65 6e 61 6d 65 90 02 1e 29 2e 47 65 74 41 63 74 69 76 65 43 32 90 02 1e 29 2e 47 65 74 56 65 72 73 69 6f 6e 90 02 1e 29 2e 47 65 74 52 65 63 6f 6e 6e 65 63 74 49 6e 74 65 72 76 61 6c 90 02 1e 29 2e 47 65 74 50 72 6f 78 79 55 52 4c 90 00 } //01 00 
		$a_03_1 = {29 2e 47 65 74 45 78 65 63 75 74 61 62 6c 65 90 02 1e 29 2e 47 65 74 4f 77 6e 65 72 90 02 1e 29 2e 47 65 74 53 65 73 73 69 6f 6e 49 44 90 02 1e 29 2e 47 65 74 43 6d 64 4c 69 6e 65 90 00 } //01 00 
		$a_03_2 = {29 2e 47 65 74 54 61 72 67 65 74 4c 6f 63 61 74 69 6f 6e 90 02 1e 29 2e 47 65 74 52 65 66 65 72 65 6e 63 65 44 4c 4c 90 02 1e 29 2e 47 65 74 54 61 72 67 65 74 44 4c 4c 90 02 1e 29 2e 47 65 74 50 72 6f 66 69 6c 65 4e 61 6d 65 90 00 } //01 00 
		$a_03_3 = {29 2e 47 65 74 55 73 65 72 6e 61 6d 65 90 02 1e 29 2e 47 65 74 50 61 73 73 77 6f 72 64 90 02 1e 29 2e 47 65 74 44 6f 6d 61 69 6e 90 02 1e 29 2e 47 65 74 52 65 71 75 65 73 74 90 00 } //01 00 
		$a_03_4 = {29 2e 47 65 74 50 72 6f 63 65 73 73 4e 61 6d 65 90 02 1e 29 2e 47 65 74 41 72 67 73 90 02 1e 29 2e 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 90 02 1e 29 2e 47 65 74 4b 69 6c 6c 90 00 } //01 00 
		$a_03_5 = {29 2e 47 65 74 52 65 6d 6f 74 65 41 64 64 72 90 02 1e 29 2e 47 65 74 53 6b 53 74 61 74 65 90 02 1e 29 2e 47 65 74 55 49 44 90 02 1e 29 2e 47 65 74 50 72 6f 63 65 73 73 90 00 } //01 00 
		$a_03_6 = {29 2e 47 65 74 45 6e 61 62 6c 65 50 54 59 90 02 1e 29 2e 47 65 74 50 69 64 90 02 1e 29 2e 47 65 74 54 75 6e 6e 65 6c 49 44 90 02 1e 29 2e 47 65 74 52 65 73 70 6f 6e 73 65 90 00 } //01 00 
		$a_03_7 = {29 2e 47 65 74 4e 65 74 49 6e 74 65 72 66 61 63 65 73 90 02 1e 29 2e 47 65 74 52 65 73 70 6f 6e 73 65 90 02 1e 29 2e 52 65 73 65 74 90 02 1e 29 2e 53 74 72 69 6e 67 90 00 } //01 00 
		$a_03_8 = {29 2e 47 65 74 48 6f 73 74 6e 61 6d 65 90 02 1e 29 2e 47 65 74 50 6f 72 74 90 02 1e 29 2e 47 65 74 43 6f 6d 6d 61 6e 64 90 02 1e 29 2e 47 65 74 50 61 73 73 77 6f 72 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}