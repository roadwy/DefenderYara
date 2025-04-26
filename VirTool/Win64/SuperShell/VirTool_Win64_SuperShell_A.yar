
rule VirTool_Win64_SuperShell_A{
	meta:
		description = "VirTool:Win64/SuperShell.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 67 65 6e 74 5c 6d 61 69 6e 2e 63 63 } //1 agent\main.cc
		$a_01_1 = {61 67 65 6e 74 5c 54 65 72 6d 69 6e 61 6c 2e 63 63 } //1 agent\Terminal.cc
		$a_01_2 = {2f 72 65 76 65 72 73 65 5f 73 73 68 2f } //1 /reverse_ssh/
		$a_01_3 = {41 67 65 6e 74 3a 3a 41 67 65 6e 74 20 65 6e 74 65 72 65 64 } //1 Agent::Agent entered
		$a_01_4 = {77 69 6e 70 74 79 5f 61 67 65 6e 74 5f 70 72 6f 63 65 73 73 } //1 winpty_agent_process
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}