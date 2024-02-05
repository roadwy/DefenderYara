
rule VirTool_Win32_Injector_gen_DI{
	meta:
		description = "VirTool:Win32/Injector.gen!DI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 6c 6f 6c 00 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 70 72 6f 6a 65 63 74 2d 37 2e 6e 65 74 00 } //01 00 
		$a_01_2 = {54 61 74 6e 69 75 6d 20 57 61 72 6e 69 6e 67 00 } //01 00 
		$a_01_3 = {8a 10 88 14 06 40 84 d2 75 f6 83 c7 0c 66 c7 41 0a eb fe 89 79 01 5f b8 01 00 00 00 5e } //00 00 
	condition:
		any of ($a_*)
 
}