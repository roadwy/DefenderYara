
rule VirTool_Win32_CeeInject_gen_EI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 75 14 8b 7d 0c 0f b6 04 17 8b bd f0 fb ff ff 01 c7 81 e7 ff 00 00 80 79 b7 4f 81 cf 00 ff ff ff 47 eb ad } //1
		$a_03_1 = {c7 44 24 04 00 00 00 00 c7 04 24 01 00 1f 00 e8 90 01 04 83 ec 0c 85 c0 74 0c 31 c0 8d 65 f4 5b 5e 5f c9 c2 10 00 c7 44 24 08 90 01 04 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 90 01 04 83 ec 0c c7 44 24 08 04 01 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}