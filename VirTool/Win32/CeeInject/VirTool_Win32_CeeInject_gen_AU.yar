
rule VirTool_Win32_CeeInject_gen_AU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 3c 03 cd 8b 94 39 08 01 00 00 8d 84 39 f8 00 00 00 8b 48 14 6a 00 52 8b 50 0c 03 56 34 8b 44 24 90 01 01 03 cf 51 52 50 ff 15 90 01 04 0f b7 4e 06 43 83 c5 28 3b d9 7c c6 90 00 } //1
		$a_03_1 = {6a 0a 6a 03 6a 00 ff 90 01 01 8b f0 85 f6 74 33 56 6a 00 ff d5 56 6a 00 8b f8 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}