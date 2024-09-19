
rule VirTool_Win32_CobalInject_A_MTB{
	meta:
		description = "VirTool:Win32/CobalInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {42 65 61 63 6f 6e 54 79 70 65 } //1 BeaconType
		$a_81_1 = {50 6f 72 74 } //1 Port
		$a_81_2 = {43 32 53 65 72 76 65 72 } //1 C2Server
		$a_81_3 = {50 72 6f 63 49 6e 6a 65 63 74 5f 45 78 65 63 75 74 65 } //1 ProcInject_Execute
		$a_81_4 = {48 74 74 70 50 6f 73 74 55 72 69 } //1 HttpPostUri
		$a_81_5 = {53 70 61 77 6e 74 6f 5f 78 } //1 Spawnto_x
		$a_81_6 = {45 76 65 6e 74 4f 62 6a 65 63 74 2e 53 68 61 32 35 36 } //-1 EventObject.Sha256
		$a_81_7 = {45 76 65 6e 74 4f 62 6a 65 63 74 53 68 61 32 35 36 } //-1 EventObjectSha256
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-1+(#a_81_7  & 1)*-1) >=6
 
}