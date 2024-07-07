
rule VirTool_Win32_CeeInject_gen_FB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 84 0a f8 00 00 00 8b 8d 90 01 02 ff ff 6b c9 28 90 00 } //1
		$a_01_1 = {83 ec 10 8b d4 8b 45 f0 89 02 8b 4d f4 89 4a 04 8b 45 f8 89 42 08 8b 4d fc 89 4a 0c 8b 55 ec 52 e8 } //1
		$a_01_2 = {b8 01 00 00 00 85 c0 74 1f 8b 4d fc 3b 4d f8 75 05 8b 45 f8 eb 15 8b 55 08 8b 45 f8 8d 4c 10 04 2b 4d 08 89 4d f8 eb d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}