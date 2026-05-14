
rule HackTool_Win64_InfestedShuttle_A_dha{
	meta:
		description = "HackTool:Win64/InfestedShuttle.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 67 65 6e 74 2e 65 78 65 20 31 39 32 2e 31 36 38 2e 31 2e 31 30 30 3a 31 32 33 34 35 } //1 agent.exe 192.168.1.100:12345
		$a_01_1 = {6d 61 69 6e 2e 72 65 61 64 53 68 61 6b 65 00 } //1
		$a_01_2 = {6d 61 69 6e 2e 43 6c 69 65 6e 74 53 68 61 6b 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}