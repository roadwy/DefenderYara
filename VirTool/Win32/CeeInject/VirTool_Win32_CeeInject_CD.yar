
rule VirTool_Win32_CeeInject_CD{
	meta:
		description = "VirTool:Win32/CeeInject.CD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 28 8b 54 24 14 2b cd c1 f9 02 3b d1 73 4c 8b 2b 8b 4c 24 44 8b 14 18 6a 0f 55 51 52 e8 90 01 04 8b 7c 24 20 8b 54 24 20 8b f0 8b cd 8b c1 c1 e9 02 f3 a5 90 00 } //1
		$a_00_1 = {8a 44 8c 18 8b 54 bc 10 0f b6 c0 89 54 8c 18 89 44 bc 10 33 d2 8d 46 01 f7 f3 8b 44 8c 1c 0f b6 14 2a 03 d0 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}