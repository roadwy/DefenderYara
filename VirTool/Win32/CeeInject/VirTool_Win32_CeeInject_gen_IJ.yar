
rule VirTool_Win32_CeeInject_gen_IJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ff ff 8b 48 50 51 8b 95 ?? ?? ff ff 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 15 } //1
		$a_03_1 = {33 c9 66 8b 48 06 39 8d ?? ?? ff ff 7d } //1
		$a_03_2 = {ff ff 8b 51 34 8b 85 ?? ?? ff ff 03 50 28 89 95 ?? ?? ff ff 90 09 04 00 8b 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}