
rule VirTool_Win64_Stowaway_A_dha{
	meta:
		description = "VirTool:Win64/Stowaway.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 6f 77 61 77 61 79 2f 61 67 65 6e 74 2f 73 68 65 6c 6c 2e 67 6f } //1 Stowaway/agent/shell.go
		$a_01_1 = {53 74 6f 77 61 77 61 79 2f 73 68 61 72 65 2f 68 65 61 72 74 62 65 61 74 2e 67 6f } //1 Stowaway/share/heartbeat.go
		$a_01_2 = {53 74 6f 77 61 77 61 79 2f 75 74 69 6c 73 2f 70 61 79 6c 6f 61 64 2e 67 6f } //1 Stowaway/utils/payload.go
		$a_01_3 = {53 74 6f 77 61 77 61 79 2f 6e 6f 64 65 2f 72 65 75 73 65 2e 67 6f } //1 Stowaway/node/reuse.go
		$a_01_4 = {53 74 6f 77 61 77 61 79 2f 61 67 65 6e 74 2f 63 6f 6d 6d 61 6e 64 2e 67 6f } //1 Stowaway/agent/command.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}