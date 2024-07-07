
rule VirTool_Win32_CeeInject_gen_GK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {88 03 43 83 c6 03 ff 4d fc 59 75 90 09 02 00 34 90 00 } //1
		$a_03_1 = {80 39 b8 75 90 01 01 80 79 09 cd 75 90 01 01 80 79 0a 2e eb 90 00 } //1
		$a_01_2 = {8b 40 3c 03 45 0c 57 8d 84 30 f8 00 00 00 } //1
		$a_01_3 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 37 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}