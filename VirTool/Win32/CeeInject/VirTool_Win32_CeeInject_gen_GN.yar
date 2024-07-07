
rule VirTool_Win32_CeeInject_gen_GN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 46 3c 8b 7c 06 78 03 fe 8b 4f 18 8b 5f 20 03 de e3 90 01 01 49 8b 04 8b 03 c6 56 57 8b f0 33 ff 33 c0 ac 85 c0 74 07 c1 cf 90 01 01 03 f8 eb f4 8b c7 5f 5e 90 02 06 75 90 01 01 8b 47 24 03 c6 66 8b 0c 48 8b 47 1c 03 c6 8b 04 88 03 c6 eb 02 33 c0 89 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_gen_GN_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8b 46 3c 8b 7c 06 78 03 fe 8b 4f 18 8b 5f 20 03 de e3 38 49 8b 04 8b 03 c6 56 57 8b f0 33 ff 33 c0 ac 85 c0 74 07 c1 cf 04 03 f8 eb f4 8b c7 5f 5e 3b 45 0c 75 db 8b 47 24 03 c6 66 8b 0c 48 8b 47 1c 03 c6 8b 04 88 03 c6 eb 02 33 c0 89 45 fc 8b 45 fc } //1
		$a_03_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 48 10 89 0d 90 01 04 8b 00 8b 48 10 89 0d 90 01 04 68 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}