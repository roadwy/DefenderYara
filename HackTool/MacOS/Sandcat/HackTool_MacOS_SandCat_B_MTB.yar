
rule HackTool_MacOS_SandCat_B_MTB{
	meta:
		description = "HackTool:MacOS/SandCat.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 69 74 72 65 2f 67 6f 63 61 74 2f 61 67 65 6e 74 } //1 mitre/gocat/agent
		$a_01_1 = {73 61 6e 64 63 61 74 2f 67 6f 63 61 74 2f 65 78 65 63 75 74 65 2f 73 68 65 6c 6c 73 } //1 sandcat/gocat/execute/shells
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 54 6f 4d 65 6d 6f 72 79 } //1 DownloadPayloadToMemory
		$a_01_3 = {67 6f 63 61 74 2f 61 67 65 6e 74 2e 67 65 74 55 73 65 72 6e 61 6d 65 } //1 gocat/agent.getUsername
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}