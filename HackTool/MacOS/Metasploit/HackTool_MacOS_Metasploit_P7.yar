
rule HackTool_MacOS_Metasploit_P7{
	meta:
		description = "HackTool:MacOS/Metasploit.P7,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 31 ff 57 48 89 e6 6a 04 5a 48 8d 4a fe 4d 31 c0 4d 31 c9 48 ff cf } //2
		$a_00_1 = {48 ff c7 b8 1d 00 00 02 0f 05 81 3c 24 4e 45 4d 4f 75 ed 48 31 c9 b8 1d 00 00 02 0f 05 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00 } //2
		$a_00_2 = {48 8b 3c 24 48 31 d2 52 57 48 89 e6 0f 05 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}