
rule VirTool_Win32_CeeInject_gen_AE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 75 05 03 46 34 eb 03 03 45 fc 89 85 } //1
		$a_01_1 = {f7 f1 8b 4d 08 0f b6 04 0b 2b c2 79 0f ba ff 00 00 00 2b d0 c1 ea 08 } //1
		$a_01_2 = {b8 68 58 4d 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}