
rule VirTool_Win32_Injector_gen_BK{
	meta:
		description = "VirTool:Win32/Injector.gen!BK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 d2 b9 ff 44 88 ff f7 f1 8d 94 3a 24 12 00 00 81 fa 24 12 00 00 } //01 00 
		$a_02_1 = {0f b6 47 04 83 c7 04 90 03 01 01 35 83 90 02 04 50 56 68 90 01 03 00 68 00 01 00 00 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}