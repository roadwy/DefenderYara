
rule HackTool_MacOS_Metasploit_P10{
	meta:
		description = "HackTool:MacOS/Metasploit.P10,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {31 c0 50 89 e7 6a 10 54 57 50 50 } //2
		$a_00_1 = {58 58 40 50 50 6a 1f 58 cd 80 } //2
		$a_00_2 = {6a 5a 58 cd 80 ff 4f f0 79 f6 } //2
		$a_00_3 = {89 e3 50 54 54 53 50 b0 3b cd 80 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}