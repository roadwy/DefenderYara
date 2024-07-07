
rule VirTool_Win32_CeeInject_gen_EN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 41 03 b9 00 01 00 00 99 f7 f9 89 d1 8b bc 95 90 01 02 ff ff 8d 04 1f bb 00 01 00 00 99 f7 fb 89 d3 8b 84 95 90 01 02 ff ff 89 84 8d 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {66 81 3b 4d 5a 0f 85 90 01 02 00 00 8b 43 3c 01 d8 a3 90 01 04 81 38 50 45 00 00 0f 85 90 01 02 00 00 8b 3d 90 01 04 c7 85 90 01 02 ff ff 07 00 01 00 c7 45 90 01 01 44 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}