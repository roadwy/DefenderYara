
rule VirTool_Win32_Injector_CG{
	meta:
		description = "VirTool:Win32/Injector.CG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 70 20 03 75 fc 8b d9 c1 e3 02 03 f3 8b 7e 0c 03 7d fc 8a 1f } //1
		$a_00_1 = {c6 45 ee 50 c6 45 ef 41 c6 45 ed 47 } //1
		$a_01_2 = {c6 45 c5 75 } //1
		$a_01_3 = {c6 45 c6 73 } //1
		$a_01_4 = {c6 45 c7 65 } //1
		$a_01_5 = {c6 45 c8 72 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}