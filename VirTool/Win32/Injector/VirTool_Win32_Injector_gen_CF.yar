
rule VirTool_Win32_Injector_gen_CF{
	meta:
		description = "VirTool:Win32/Injector.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 90 01 02 ff ff ff 55 90 01 01 89 85 90 01 02 ff ff 6a 00 ff 77 54 ff 75 90 01 01 ff b5 90 01 02 ff ff ff b5 90 01 02 ff ff ff 55 90 00 } //01 00 
		$a_03_1 = {66 3b 77 06 72 90 14 6b c6 28 90 00 } //01 00 
		$a_03_2 = {ff ff 02 00 01 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_01_3 = {e8 06 00 00 00 6e 74 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}