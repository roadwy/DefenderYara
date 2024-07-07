
rule VirTool_Win32_CeeInject_gen_LD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 9d fa ff ff 71 c6 85 9e fa ff ff 66 c6 85 9f fa ff ff 7a c6 85 a0 fa ff ff 71 c6 85 a1 fa ff ff 78 c6 85 a2 fa ff ff 27 c6 85 a3 fa ff ff 26 c6 85 a4 fa ff ff 3a c6 85 a5 fa ff ff 70 c6 85 a6 fa ff ff 78 c6 85 a7 fa ff ff 78 c6 85 a8 fa ff ff 00 33 c9 } //1
		$a_01_1 = {8b 95 e0 fa ff ff 83 c2 01 89 95 e0 fa ff ff 83 bd e0 fa ff ff 0c 7d 37 c7 85 cc f9 ff ff c6 00 00 00 8b 85 e0 fa ff ff 0f be 8c 05 9c fa ff ff 81 f1 14 07 00 00 8b 95 e0 fa ff ff 88 8c 15 9c fa ff ff c7 85 d0 f9 ff ff 9e 01 00 00 eb b1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}