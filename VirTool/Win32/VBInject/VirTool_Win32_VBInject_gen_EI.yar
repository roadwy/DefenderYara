
rule VirTool_Win32_VBInject_gen_EI{
	meta:
		description = "VirTool:Win32/VBInject.gen!EI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 02 8b 55 a8 66 33 0c 7a ff 15 90 01 04 8b 4d bc 8b 5d e0 8b 51 0c 8b 4d c0 88 04 32 8b 75 e8 b8 01 00 00 00 03 c1 0f 80 90 00 } //01 00 
		$a_03_1 = {74 3e 66 83 39 01 75 38 8b f3 8b 45 90 01 01 6b f6 28 8b 51 14 0f 80 90 01 04 03 f0 8b 41 10 0f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}