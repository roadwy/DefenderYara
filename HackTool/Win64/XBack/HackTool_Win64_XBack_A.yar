
rule HackTool_Win64_XBack_A{
	meta:
		description = "HackTool:Win64/XBack.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 20 3c 61 64 64 72 3a 70 6f 72 74 3e 20 3c 42 6f 74 49 64 5f 33 32 63 68 61 72 73 3e 20 3c 74 61 67 3d 73 63 68 65 6d 65 3a 2f 2f 64 65 73 74 3e } //1 exe <addr:port> <BotId_32chars> <tag=scheme://dest>
		$a_01_1 = {43 61 6e 27 74 20 70 61 72 73 65 20 3c 72 6f 75 74 65 72 5f 69 70 3a 70 6f 72 74 3e 0a 00 00 00 43 61 6e 27 74 20 70 61 72 73 65 20 65 6e 64 70 6f 69 6e 74 20 2d 20 27 25 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}