
rule VirTool_Win32_CeeInject_gen_LC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 55 f8 0f b6 04 02 8b 55 f8 8b 4d 10 89 45 fc 8b c2 99 f7 f9 8b 45 0c 0f b6 04 02 8b 55 fc 33 d0 8b 45 08 8b 4d f8 88 14 01 ff 45 f8 8b 45 f8 8b 55 14 3b c2 7c c6 c9 c3 } //1
		$a_01_1 = {c7 85 e4 fd ff ff 8d 00 00 00 8b 85 e4 fd ff ff f7 d8 05 ba 00 00 00 89 85 e8 fd ff ff 8d 85 28 fd ff ff ba 30 30 00 10 8b f8 8b f2 b9 24 00 00 00 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 83 c4 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}