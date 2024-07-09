
rule VirTool_Win32_DelfInject_gen_BQ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 47 28 03 45 ?? 89 45 } //2
		$a_01_1 = {0f 01 4d f5 0f b6 45 fa 3c e8 74 04 3c ff 75 02 } //2
		$a_01_2 = {66 81 3b 4d 5a 0f 85 } //1
		$a_01_3 = {81 3f 50 45 00 00 0f 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}