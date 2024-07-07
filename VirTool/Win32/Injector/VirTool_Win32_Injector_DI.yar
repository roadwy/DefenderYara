
rule VirTool_Win32_Injector_DI{
	meta:
		description = "VirTool:Win32/Injector.DI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 8b 10 c1 e2 90 01 01 33 10 81 c2 90 01 04 89 10 8b 00 c1 e8 90 01 01 c3 90 00 } //1
		$a_03_1 = {89 04 24 33 ff 51 6a 00 6a 90 01 01 ff 15 90 01 04 8b f0 85 f6 74 2c 6a 04 68 00 10 00 00 55 6a 00 56 ff 15 90 01 04 8b d8 85 db 74 15 8d 44 24 04 50 55 8b 44 24 08 50 53 56 ff 15 90 00 } //1
		$a_03_2 = {8b d8 8d 55 b8 b8 90 01 04 e8 90 01 04 8b 45 b8 8b d6 b9 01 00 00 00 e8 90 01 04 48 75 2a a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}