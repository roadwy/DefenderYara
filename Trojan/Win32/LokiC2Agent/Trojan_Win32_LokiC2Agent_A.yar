
rule Trojan_Win32_LokiC2Agent_A{
	meta:
		description = "Trojan:Win32/LokiC2Agent.A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 04 00 0d 00 00 "
		
	strings :
		$a_81_0 = {65 78 65 63 75 74 65 2d 62 6f 66 2d 6e 6f 64 65 } //2 execute-bof-node
		$a_81_1 = {65 78 65 63 75 74 65 2d 61 73 73 65 6d 62 6c 79 2d 6e 6f 64 65 } //2 execute-assembly-node
		$a_81_2 = {65 78 65 63 75 74 65 2d 73 63 65 78 65 63 2d 6e 6f 64 65 } //2 execute-scexec-node
		$a_81_3 = {62 6f 66 2d 63 6f 6d 70 6c 65 74 65 } //1 bof-complete
		$a_81_4 = {61 73 73 65 6d 62 6c 79 2d 63 6f 6d 70 6c 65 74 65 } //1 assembly-complete
		$a_81_5 = {73 63 65 78 65 63 2d 63 6f 6d 70 6c 65 74 65 } //1 scexec-complete
		$a_81_6 = {43 4f 46 46 4c 6f 61 64 65 72 2e 6e 6f 64 65 } //2 COFFLoader.node
		$a_81_7 = {61 73 73 65 6d 62 6c 79 2e 6e 6f 64 65 } //1 assembly.node
		$a_81_8 = {73 63 65 78 65 63 2e 6e 6f 64 65 } //1 scexec.node
		$a_81_9 = {65 78 65 63 75 74 65 5f 61 73 73 65 6d 62 6c 79 } //1 execute_assembly
		$a_81_10 = {72 75 6e 43 4f 46 46 } //1 runCOFF
		$a_81_11 = {72 75 6e 5f 61 72 72 61 79 } //1 run_array
		$a_81_12 = {73 6f 63 6b 73 2d 70 72 6f 78 79 } //1 socks-proxy
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*2+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=4
 
}