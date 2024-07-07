
rule VirTool_Win32_CeeInject_gen_EC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 46 28 03 46 34 90 01 01 89 87 b0 00 00 00 90 00 } //1
		$a_01_1 = {81 3b 47 65 74 50 74 06 83 c7 04 41 eb ed 81 7b 04 72 6f 63 41 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}