
rule VirTool_Win32_CeeInject_gen_HO{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 02 07 00 01 00 } //1
		$a_01_1 = {8b 48 50 8b 50 34 6a 40 68 00 30 00 00 } //1
		$a_03_2 = {8b 48 28 03 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 89 8a b0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}