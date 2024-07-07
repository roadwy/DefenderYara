
rule VirTool_MacOS_Myrddyn_A_MTB{
	meta:
		description = "VirTool:MacOS/Myrddyn.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 4d 79 74 68 69 63 2f 61 67 65 6e 74 5f 63 6f 64 65 2f 70 6f 73 65 69 64 6f 6e 2e 67 6f } //2 /Mythic/agent_code/poseidon.go
		$a_00_1 = {2f 4d 79 74 68 69 63 2f 61 67 65 6e 74 5f 63 6f 64 65 2f 6b 65 79 6c 6f 67 2f 6b 65 79 6c 6f 67 2e 67 6f } //1 /Mythic/agent_code/keylog/keylog.go
		$a_00_2 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 2e 67 6f } //1 screencapture.go
		$a_00_3 = {61 67 65 6e 74 5f 63 6f 64 65 2f 70 65 72 73 69 73 74 5f 6c 61 75 6e 63 68 64 } //1 agent_code/persist_launchd
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}