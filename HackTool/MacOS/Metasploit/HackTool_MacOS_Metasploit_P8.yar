
rule HackTool_MacOS_Metasploit_P8{
	meta:
		description = "HackTool:MacOS/Metasploit.P8,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 49 89 c4 48 89 c7 b8 62 00 00 02 48 31 f6 56 } //2
		$a_00_1 = {56 48 89 e6 6a 10 5a 0f 05 } //2
		$a_00_2 = {b8 5a 00 00 02 48 c7 c6 02 00 00 00 0f 05 b8 5a 00 00 02 48 c7 c6 01 00 00 00 0f 05 b8 5a 00 00 02 48 c7 c6 00 00 00 00 0f 05 } //2
		$a_00_3 = {48 31 c0 b8 3b 00 00 02 e8 09 00 00 00 } //2
		$a_00_4 = {5f 48 31 d2 52 57 48 89 e6 0f 05 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}