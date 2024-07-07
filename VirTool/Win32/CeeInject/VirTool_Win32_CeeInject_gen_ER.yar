
rule VirTool_Win32_CeeInject_gen_ER{
	meta:
		description = "VirTool:Win32/CeeInject.gen!ER,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 50 68 90 01 04 6a 0c e8 90 01 04 83 c4 08 50 ff 15 90 01 04 50 ff 15 90 01 04 89 45 90 01 01 8b 45 90 01 01 50 ff 55 90 01 01 8b e5 90 00 } //1
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 68 90 01 04 ff 55 90 01 01 ff 55 90 01 01 89 45 90 01 01 81 7d 90 01 01 14 07 00 00 0f 85 90 01 02 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}