
rule HackTool_MacOS_Metasploit_P6{
	meta:
		description = "HackTool:MacOS/Metasploit.P6,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 } //2
		$a_00_1 = {56 48 89 e6 6a 10 5a 0f 05 b8 6a 00 00 02 48 31 f6 48 ff c6 49 89 fc 0f 05 b8 1e 00 00 02 4c 89 e7 48 89 e6 48 89 e2 48 83 ea 04 0f 05 } //2
		$a_00_2 = {48 89 c7 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00 } //2
		$a_00_3 = {48 8b 3c 24 48 31 d2 52 57 48 89 e6 0f 05 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}