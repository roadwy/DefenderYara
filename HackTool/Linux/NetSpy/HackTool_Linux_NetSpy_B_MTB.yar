
rule HackTool_Linux_NetSpy_B_MTB{
	meta:
		description = "HackTool:Linux/NetSpy.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 73 70 79 } //1 netspy/core/spy
		$a_01_1 = {70 6f 6c 6c 2e 73 70 6c 69 63 65 50 69 70 65 } //1 poll.splicePipe
		$a_01_2 = {48 89 ce 48 8d 05 a9 e8 01 00 e8 a4 ba df ff 48 8d 05 fd e0 03 00 e8 b8 56 df ff 48 89 84 24 e8 00 00 00 48 c7 40 08 04 00 00 00 48 8b 54 24 30 48 89 50 10 83 3d 88 f2 28 00 00 75 0d 48 8b 8c 24 88 01 00 00 48 89 08 eb 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}