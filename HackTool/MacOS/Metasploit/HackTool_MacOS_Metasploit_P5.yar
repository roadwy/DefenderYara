
rule HackTool_MacOS_Metasploit_P5{
	meta:
		description = "HackTool:MacOS/Metasploit.P5,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 } //2
		$a_00_1 = {b8 6a 00 00 02 48 31 f6 48 ff c6 49 89 fc 0f 05 b8 1e 00 00 02 4c 89 e7 48 89 e6 48 89 e2 48 83 ea 04 0f 05 } //2
		$a_00_2 = {b8 1d 00 00 02 48 31 c9 51 48 89 e6 ba 04 00 00 00 4d 31 c0 4d 31 d2 0f 05 } //2
		$a_00_3 = {b8 c5 00 00 02 48 31 ff 48 ff cf ba 07 00 00 00 41 ba 02 10 00 00 49 89 f8 4d 31 c9 0f 05 48 89 c6 56 } //2
		$a_00_4 = {4c 89 ef 48 31 c9 4c 89 da 4d 31 c0 4d 31 d2 b8 1d 00 00 02 0f 05 58 ff d0 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}