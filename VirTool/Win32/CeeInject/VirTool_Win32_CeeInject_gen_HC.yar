
rule VirTool_Win32_CeeInject_gen_HC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 07 00 01 00 } //1
		$a_01_1 = {ff 76 54 03 c7 50 ff 76 34 } //1
		$a_03_2 = {03 46 34 89 85 90 09 09 00 [0-06] 8b 46 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}