
rule HackTool_Linux_SAgnt_B_MTB{
	meta:
		description = "HackTool:Linux/SAgnt.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 3f e8 26 99 77 71 56 05 11 6b 9b cf 1c b7 31 a7 bb dc 46 9c b1 12 f1 36 62 45 d6 6f 38 d7 33 c7 8f a8 42 dd 1d 2a 35 f4 89 0b 56 12 15 6d e8 ce ee 75 1b dd 2b 89 f2 36 0c 64 e9 b9 28 ae 03 e2 6a 5d 30 4e 4c aa 65 9e 6e 8e 1e dd } //1
		$a_01_1 = {6d 47 88 6a 0d ce e4 14 7a 29 36 1e ea 84 ce d6 38 a7 e1 6c 88 e9 bf fa 64 7d d3 a4 a4 2d b0 fa 58 32 99 9c 9c d4 df a6 d8 91 49 dd d5 f7 c9 e9 74 6c 72 2c 16 4b c6 92 4d b1 71 4d b1 c9 35 b1 d8 a4 f4 a4 d2 c7 24 15 b3 5b e3 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}