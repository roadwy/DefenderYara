
rule VirTool_Win32_CeeInject_gen_GP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 70 28 68 00 00 40 00 e8 } //1
		$a_03_1 = {ff 70 34 ff 35 90 01 04 ff 15 90 01 04 6a 00 68 00 30 00 00 8b 85 e0 cf ff ff ff 70 50 90 00 } //1
		$a_03_2 = {07 00 01 00 90 09 03 00 c7 45 90 00 } //1
		$a_03_3 = {0f b6 09 33 c8 a1 90 01 04 03 05 90 01 04 88 08 8b 85 90 01 04 40 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}