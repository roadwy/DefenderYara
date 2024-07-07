
rule VirTool_Win32_Tetanus_A_MTB{
	meta:
		description = "VirTool:Win32/Tetanus.A!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 63 61 72 67 6f 2f 72 65 67 69 73 74 72 79 2f 73 72 63 2f } //1 .cargo/registry/src/
		$a_01_1 = {41 67 65 6e 74 54 61 73 6b 63 6f 6d 6d 61 6e 64 } //1 AgentTaskcommand
		$a_01_2 = {62 61 63 6b 67 72 6f 75 6e 64 5f 74 61 73 6b 73 } //1 background_tasks
		$a_01_3 = {6b 69 6c 6c 61 62 6c 65 } //1 killable
		$a_01_4 = {75 73 65 72 5f 6f 75 74 70 75 74 63 6f 6d 70 6c 65 74 65 64 } //1 user_outputcompleted
		$a_01_5 = {65 6e 63 5f 6b 65 79 64 65 63 5f 6b 65 79 } //1 enc_keydec_key
		$a_01_6 = {4d 79 74 68 69 63 46 69 6c 65 } //1 MythicFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}