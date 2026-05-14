
rule HackTool_MacOS_Metasploit_P9{
	meta:
		description = "HackTool:MacOS/Metasploit.P9,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {31 c0 99 50 40 50 40 50 52 b0 61 cd 80 72 6c 89 c7 } //2
		$a_00_1 = {89 e3 6a 10 53 57 52 b0 62 cd 80 72 51 } //2
		$a_00_2 = {89 e5 83 ec 08 31 c9 f7 e1 51 89 e6 b0 04 50 56 57 50 48 cd 80 } //2
		$a_00_3 = {31 c0 50 50 48 50 40 66 b8 02 10 50 31 c0 b0 07 50 56 52 52 b0 c5 cd 80 } //2
		$a_00_4 = {56 89 d8 29 f0 50 57 52 31 c0 b0 03 cd 80 72 08 29 c3 29 c6 75 ea } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}