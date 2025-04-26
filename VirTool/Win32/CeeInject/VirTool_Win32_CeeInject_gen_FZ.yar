
rule VirTool_Win32_CeeInject_gen_FZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 a1 ?? ?? ?? ?? ff 70 50 a1 ?? ?? ?? ?? ff 70 34 } //1
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 05 } //1
		$a_03_2 = {8b 40 34 8b 0d ?? ?? ?? ?? 03 41 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}