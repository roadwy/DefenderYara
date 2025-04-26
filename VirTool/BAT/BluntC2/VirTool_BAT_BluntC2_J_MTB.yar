
rule VirTool_BAT_BluntC2_J_MTB{
	meta:
		description = "VirTool:BAT/BluntC2.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {2e 43 6f 6d 6d 61 6e 64 73 2e 45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 } //1 .Commands.ExecuteAssembly
		$a_81_1 = {2e 43 6f 6d 6d 61 6e 64 73 2e 4d 61 6b 65 54 6f 6b 65 6e } //1 .Commands.MakeToken
		$a_81_2 = {2e 4d 65 73 73 61 67 65 73 } //1 .Messages
		$a_81_3 = {48 61 6e 64 6c 65 52 65 76 65 72 73 65 50 6f 72 74 46 6f 72 77 61 72 64 50 61 63 6b 65 74 } //1 HandleReversePortForwardPacket
		$a_81_4 = {67 65 74 5f 53 70 61 77 6e 54 6f } //1 get_SpawnTo
		$a_81_5 = {52 65 76 65 72 73 65 50 6f 72 74 46 6f 72 77 61 72 64 53 74 61 74 65 } //1 ReversePortForwardState
		$a_81_6 = {44 72 6f 6e 65 43 6f 6d 6d 61 6e 64 } //1 DroneCommand
		$a_81_7 = {2e 43 6f 6d 6d 61 6e 64 73 2e 53 74 65 61 6c 54 6f 6b 65 6e } //1 .Commands.StealToken
		$a_81_8 = {2e 43 6f 6d 6d 61 6e 64 73 2e 53 68 65 6c 6c } //1 .Commands.Shell
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}