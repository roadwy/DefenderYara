
rule VirTool_Win32_CeeInject_gen_FY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 76 50 ff 76 34 } //1
		$a_01_1 = {8b 47 0c 03 46 34 } //1
		$a_03_2 = {07 00 01 00 90 09 03 00 c7 45 90 00 } //1
		$a_03_3 = {56 8b cf 80 f3 08 e8 90 01 04 46 88 18 83 fe 90 01 01 72 e7 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}