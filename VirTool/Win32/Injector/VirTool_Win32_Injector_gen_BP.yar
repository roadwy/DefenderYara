
rule VirTool_Win32_Injector_gen_BP{
	meta:
		description = "VirTool:Win32/Injector.gen!BP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 51 0b 32 96 90 01 04 32 d1 80 f2 90 01 01 88 96 90 01 04 83 f9 05 7e 04 33 c9 eb 01 41 46 81 fe 90 01 04 7c d9 90 00 } //1
		$a_03_1 = {6a 2e 58 66 89 85 90 01 02 ff ff 6a 6c 58 66 89 85 90 01 02 ff ff 6a 6f 58 66 89 85 90 01 02 ff ff 6a 67 90 00 } //1
		$a_03_2 = {0f b7 40 02 39 85 90 01 02 ff ff 7d 3f 8b 85 90 01 02 ff ff 6b c0 28 8b 4d f0 ff 74 01 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}