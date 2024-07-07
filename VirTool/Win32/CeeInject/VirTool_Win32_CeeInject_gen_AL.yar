
rule VirTool_Win32_CeeInject_gen_AL{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 } //1
		$a_01_1 = {46 81 fe 81 57 03 00 7c } //1
		$a_01_2 = {b9 e8 03 00 00 03 c2 33 d2 f7 f1 8a 1c 2e 2b da } //1
		$a_03_3 = {8b 55 28 8b 45 34 03 d0 89 94 24 90 01 02 00 00 eb 90 01 01 8b 55 28 03 d1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}