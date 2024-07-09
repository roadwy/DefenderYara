
rule VirTool_Win32_CeeInject_gen_DT{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {88 51 f0 30 10 fe cb 0f b6 14 0e 88 11 75 e8 } //1
		$a_01_1 = {0f b7 0e 8b c1 25 ff 0f 00 00 03 02 81 e1 00 f0 00 00 81 f9 00 30 00 00 75 06 } //1
		$a_03_2 = {6a 00 6a 01 8d 4d ff 51 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 80 7d ff e9 75 13 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}