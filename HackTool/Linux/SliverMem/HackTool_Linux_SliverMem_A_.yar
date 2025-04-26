
rule HackTool_Linux_SliverMem_A_{
	meta:
		description = "HackTool:Linux/SliverMem.A!!SliverMem.A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_81_0 = {73 6c 69 76 65 72 70 62 } //3 sliverpb
		$a_81_1 = {42 65 61 63 6f 6e } //1 Beacon
		$a_81_2 = {52 65 67 69 73 74 65 72 2e 4a 69 74 74 65 72 } //1 Register.Jitter
		$a_81_3 = {52 65 67 69 73 74 65 72 2e 4e 65 78 74 43 68 65 63 6b 69 6e } //1 Register.NextCheckin
		$a_81_4 = {4f 70 65 6e 53 65 73 73 69 6f 6e 2e 43 32 73 } //1 OpenSession.C2s
		$a_81_5 = {49 6e 76 6f 6b 65 53 70 61 77 6e 44 6c 6c } //1 InvokeSpawnDll
		$a_81_6 = {53 6f 63 6b 54 61 62 45 6e 74 72 79 } //1 SockTabEntry
		$a_81_7 = {52 70 6f 72 74 46 77 64 4c 69 73 74 65 6e 65 72 } //1 RportFwdListener
		$a_81_8 = {4d 65 6d 66 69 6c 65 73 52 6d } //1 MemfilesRm
		$a_81_9 = {54 75 6e 6e 65 6c 49 44 } //1 TunnelID
		$a_81_10 = {42 65 61 63 6f 6e 54 61 73 6b 73 } //1 BeaconTasks
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=10
 
}