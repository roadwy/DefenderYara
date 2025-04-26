
rule VirTool_WinNT_Grolf_A{
	meta:
		description = "VirTool:WinNT/Grolf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 05 8b 4d 1c eb f3 c7 45 30 0f 00 00 c0 8b 06 85 c0 74 07 } //1
		$a_01_1 = {83 e8 05 89 43 01 c6 03 e9 8b c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}