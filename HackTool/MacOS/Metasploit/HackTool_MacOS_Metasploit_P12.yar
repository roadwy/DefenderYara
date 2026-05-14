
rule HackTool_MacOS_Metasploit_P12{
	meta:
		description = "HackTool:MacOS/Metasploit.P12,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {31 c0 99 50 40 50 40 50 52 b0 61 cd 80 72 6d 89 c7 } //2
		$a_00_1 = {89 e3 6a 10 53 57 52 b0 62 cd 80 72 52 } //2
		$a_00_2 = {31 db 83 eb 01 43 53 57 53 b0 5a cd 80 72 43 83 fb 03 75 f1 } //2
		$a_00_3 = {31 c0 50 50 50 50 b0 3b cd 80 } //2
		$a_00_4 = {89 e3 50 50 53 50 b0 3b cd 80 31 c0 50 89 e3 50 50 53 50 50 b0 07 cd 80 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}