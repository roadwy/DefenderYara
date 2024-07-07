
rule VirTool_Win32_CeeInject_gen_IS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 48 14 83 e9 70 83 c4 10 89 4d f8 33 c0 b1 90 01 01 30 88 90 01 04 40 83 f8 90 01 01 7c f4 8b 45 f4 50 05 ff 0f 00 00 03 45 f8 8d 35 90 1b 01 ff d6 90 00 } //1
		$a_03_1 = {0f b7 45 f0 2d dc 07 00 00 d0 e0 33 c9 90 03 01 01 04 2c 90 01 01 8b 15 90 01 04 30 04 0a 41 83 f9 5a 7c f1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}