
rule VirTool_Win32_Feline_A_MTB{
	meta:
		description = "VirTool:Win32/Feline.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 63 2f 73 65 72 76 65 72 2e 28 2a 61 75 67 57 72 69 74 65 72 29 2e 57 72 69 74 65 } //01 00  xc/server.(*augWriter).Write
		$a_01_1 = {78 63 2f 73 65 72 76 65 72 2e 6c 66 77 64 } //01 00  xc/server.lfwd
		$a_01_2 = {78 63 2f 73 65 72 76 65 72 2e 68 61 6e 64 6c 65 43 6d 64 } //00 00  xc/server.handleCmd
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Feline_A_MTB_2{
	meta:
		description = "VirTool:Win32/Feline.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 63 2f 73 65 72 76 65 72 2f 73 65 72 76 65 72 2e 67 6f } //01 00  xc/server/server.go
		$a_01_1 = {78 63 2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00  xc/client/client_windows.go
		$a_01_2 = {78 63 2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 2e 67 6f } //01 00  xc/client/client.go
		$a_01_3 = {78 63 2f 76 75 6c 6e 73 2f 76 75 6c 6e 73 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00  xc/vulns/vulns_windows.go
		$a_81_4 = {78 63 2f 73 68 65 6c 6c 2e 53 74 61 72 74 53 53 48 53 65 72 76 65 72 } //00 00  xc/shell.StartSSHServer
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Feline_A_MTB_3{
	meta:
		description = "VirTool:Win32/Feline.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 63 2f 6c 6f 61 64 2e 67 6f } //01 00  xc/load.go
		$a_01_1 = {73 79 73 63 61 6c 6c 2f 7a 73 79 73 63 61 6c 6c 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00  syscall/zsyscall_windows.go
		$a_01_2 = {6d 61 69 6e 2e 42 61 6b 65 } //01 00  main.Bake
		$a_03_3 = {31 c0 48 8b 8c 24 50 05 00 00 87 81 28 03 00 00 b8 01 00 00 00 f0 0f c1 81 00 03 00 00 48 8b 05 30 39 52 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 90 01 04 48 8b 05 ce 39 52 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 90 01 04 48 8b ac 24 40 05 00 00 48 81 c4 48 05 00 00 c3 90 00 } //01 00 
		$a_03_4 = {48 89 6c 24 30 48 8d 90 01 03 48 8b 44 24 48 48 89 04 24 48 8b 44 24 40 48 89 44 24 08 e8 90 01 04 48 8b 90 01 05 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 40 48 89 44 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 90 01 04 48 8b 44 24 28 48 89 44 24 50 48 8b 6c 24 30 48 83 c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Feline_A_MTB_4{
	meta:
		description = "VirTool:Win32/Feline.A!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 63 2f 73 65 72 76 65 72 2e 66 6f 72 77 61 72 64 } //01 00  xc/server.forward
		$a_01_1 = {78 63 2f 73 65 72 76 65 72 2e 65 78 69 74 } //01 00  xc/server.exit
		$a_01_2 = {78 63 2f 73 65 72 76 65 72 2e 68 61 6e 64 6c 65 43 6d 64 } //01 00  xc/server.handleCmd
		$a_01_3 = {78 63 2f 73 65 72 76 65 72 2e 73 65 6e 64 52 65 61 64 65 72 } //01 00  xc/server.sendReader
		$a_01_4 = {79 61 6d 75 78 } //00 00  yamux
	condition:
		any of ($a_*)
 
}