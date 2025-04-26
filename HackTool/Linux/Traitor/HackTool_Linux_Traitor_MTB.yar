
rule HackTool_Linux_Traitor_MTB{
	meta:
		description = "HackTool:Linux/Traitor!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 69 72 74 79 54 68 61 74 50 69 70 65 } //1 dirtyThatPipe
		$a_00_1 = {64 6f 63 6b 65 72 73 6f 63 6b 2e 77 72 69 74 61 62 6c 65 44 6f 63 6b 65 72 53 6f 63 6b 65 74 45 78 70 6c 6f 69 74 } //1 dockersock.writableDockerSocketExploit
		$a_00_2 = {70 6f 6c 6c 2e 73 70 6c 69 63 65 50 69 70 65 } //1 poll.splicePipe
		$a_00_3 = {6c 69 61 6d 67 2f 74 72 61 69 74 6f 72 } //1 liamg/traitor
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}