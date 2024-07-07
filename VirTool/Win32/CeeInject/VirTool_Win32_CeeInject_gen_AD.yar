
rule VirTool_Win32_CeeInject_gen_AD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 48 28 03 48 34 eb 09 8b 4c 24 90 01 01 8b 49 28 03 c8 90 00 } //1
		$a_01_1 = {f7 f3 0f b6 19 2b da 79 06 81 c3 00 01 00 00 8b 44 24 } //1
		$a_01_2 = {b8 68 58 4d 56 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}