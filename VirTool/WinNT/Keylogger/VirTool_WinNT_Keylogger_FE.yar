
rule VirTool_WinNT_Keylogger_FE{
	meta:
		description = "VirTool:WinNT/Keylogger.FE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 80 21 10 80 75 } //1
		$a_01_1 = {81 f9 80 21 10 80 75 } //1
		$a_01_2 = {3d 84 21 10 80 75 } //1
		$a_01_3 = {81 f9 84 21 10 80 75 } //1
		$a_01_4 = {68 ed 00 00 00 6a 60 ff 15 } //4
		$a_01_5 = {6d 73 65 70 73 2e 70 64 62 00 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4) >=10
 
}