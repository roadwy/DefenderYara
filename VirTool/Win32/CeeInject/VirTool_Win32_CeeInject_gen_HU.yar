
rule VirTool_Win32_CeeInject_gen_HU{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 46 50 8b 4e 34 8b 15 90 01 04 6a 00 68 00 30 00 00 50 51 52 e8 90 00 } //1
		$a_03_1 = {0f b7 56 06 3b c2 72 90 09 0b 00 a1 90 01 04 40 a3 90 00 } //1
		$a_03_2 = {8b 56 28 8b 7e 34 8b 0d 90 01 04 8d 44 24 90 01 01 50 03 d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}