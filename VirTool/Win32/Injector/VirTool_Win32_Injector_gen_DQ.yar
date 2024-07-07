
rule VirTool_Win32_Injector_gen_DQ{
	meta:
		description = "VirTool:Win32/Injector.gen!DQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {83 f8 10 77 07 b8 03 00 00 00 ff e0 fc } //1
		$a_01_1 = {81 f9 00 01 00 00 } //1
		$a_01_2 = {66 83 c1 03 } //1
		$a_01_3 = {0f b7 47 14 } //1
		$a_01_4 = {bb 00 00 40 00 } //1
		$a_01_5 = {66 3b 77 06 } //1 㭦ٷ
		$a_03_6 = {56 8b 0e fc 90 02 0f 64 8b 89 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=6
 
}