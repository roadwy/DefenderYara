
rule HackTool_MacOS_Metasploit_P14{
	meta:
		description = "HackTool:MacOS/Metasploit.P14,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {c5 c0 a0 e3 00 00 20 e0 02 15 a0 e3 07 20 a0 e3 01 3a a0 e3 00 40 e0 e3 05 50 25 e0 80 00 00 ef 00 b0 a0 e1 02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 61 c0 a0 e3 80 00 00 ef 00 a0 a0 e1 } //2
		$a_00_1 = {10 20 a0 e3 68 c0 a0 e3 80 00 00 ef 0a 00 a0 e1 01 10 a0 e3 6a c0 a0 e3 80 00 00 ef 1e c0 a0 e3 0a 00 a0 e1 10 10 a0 e3 18 10 0d e5 10 20 4d e2 18 30 4d e2 80 00 00 ef } //2
		$a_00_2 = {0a 00 a0 e1 06 c0 a0 e3 80 00 00 ef 07 a0 a0 e1 03 c0 a0 e3 0a 00 a0 e1 0b 10 a0 e1 04 20 a0 e3 80 00 00 ef 00 90 9b e4 0b 80 a0 e1 } //2
		$a_00_3 = {03 c0 a0 e3 0a 00 a0 e1 08 10 a0 e1 09 20 a0 e1 80 00 00 ef 00 00 50 e3 04 00 00 ba 00 80 88 e0 00 90 49 e0 00 00 59 e3 f4 ff ff 1a 00 f0 8b e2 01 c0 a0 e3 80 00 00 ef } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}