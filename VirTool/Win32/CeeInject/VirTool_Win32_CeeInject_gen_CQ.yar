
rule VirTool_Win32_CeeInject_gen_CQ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 38 7b 75 3f 8b 45 f0 03 45 0c 40 80 38 7d 75 33 c7 04 24 04 01 00 00 } //1
		$a_03_1 = {8b 45 0c 03 45 f8 80 38 7b 0f 85 ?? ?? ?? ?? 8b 45 f8 03 45 0c 40 80 38 61 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}