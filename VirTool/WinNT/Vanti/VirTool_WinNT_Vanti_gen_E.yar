
rule VirTool_WinNT_Vanti_gen_E{
	meta:
		description = "VirTool:WinNT/Vanti.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 9d 8f a0 c3 } //1
		$a_01_1 = {05 e4 9a ce 14 } //1
		$a_01_2 = {68 00 0c 00 00 50 6a 0b ff } //2
		$a_03_3 = {20 32 54 76 98 0f 84 90 01 01 01 00 00 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=5
 
}