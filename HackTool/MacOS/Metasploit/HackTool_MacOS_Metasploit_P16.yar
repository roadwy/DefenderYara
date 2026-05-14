
rule HackTool_MacOS_Metasploit_P16{
	meta:
		description = "HackTool:MacOS/Metasploit.P16,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 61 c0 a0 e3 80 00 00 ef 00 a0 a0 e1 } //2
		$a_00_1 = {0a 00 a0 e1 0e 10 a0 e1 10 20 a0 e3 68 c0 a0 e3 80 00 00 ef 0a 00 a0 e1 01 10 a0 e3 6a c0 a0 e3 80 00 00 ef } //2
		$a_00_2 = {1e c0 a0 e3 0a 00 a0 e1 10 10 a0 e3 18 10 0d e5 10 20 4d e2 18 30 4d e2 80 00 00 ef 00 b0 a0 e1 02 50 a0 e3 5a c0 a0 e3 0b 00 a0 e1 05 10 a0 e1 80 00 00 ef } //2
		$a_00_3 = {05 50 45 e0 0d 60 a0 e1 20 d0 4d e2 14 00 8f e2 00 00 86 e4 04 50 86 e5 06 10 a0 e1 00 20 a0 e3 3b c0 a0 e3 80 00 00 ef } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}