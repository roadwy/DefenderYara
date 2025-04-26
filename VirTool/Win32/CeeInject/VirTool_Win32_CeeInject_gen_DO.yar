
rule VirTool_Win32_CeeInject_gen_DO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 19 88 18 88 11 8a 00 8b 4d 10 03 c2 23 c6 8a 84 05 f0 fe ff ff 32 04 39 88 07 47 ff 4d 0c 75 bc } //1
		$a_01_1 = {0f b7 46 14 83 65 0c 00 66 83 7e 06 00 c7 45 fc 01 00 00 00 8d 7c 30 18 76 41 } //1
		$a_03_2 = {8b 44 b5 d8 80 38 00 74 ?? 50 8d 85 d4 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}