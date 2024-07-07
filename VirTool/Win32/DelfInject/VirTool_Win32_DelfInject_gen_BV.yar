
rule VirTool_Win32_DelfInject_gen_BV{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 1b 00 8b 40 34 90 00 } //2
		$a_03_1 = {8b 40 34 89 45 90 01 01 6a 04 68 00 30 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 1b 00 90 00 } //2
		$a_01_2 = {0f b7 40 06 48 85 c0 72 } //1
		$a_01_3 = {3c e8 74 04 3c ff 75 02 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}