
rule VirTool_Win32_VBInject_gen_HK{
	meta:
		description = "VirTool:Win32/VBInject.gen!HK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b c9 28 8d 84 08 f8 00 00 00 } //01 00 
		$a_01_1 = {8d 45 e0 50 8b 45 08 8b 00 ff 75 08 ff 50 1c 89 45 d8 83 7d d8 00 7d 17 } //01 00 
		$a_01_2 = {2b c1 83 e8 05 50 8b 45 08 8b 00 ff 75 08 ff 50 } //00 00 
	condition:
		any of ($a_*)
 
}