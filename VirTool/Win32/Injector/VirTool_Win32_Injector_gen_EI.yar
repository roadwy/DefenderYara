
rule VirTool_Win32_Injector_gen_EI{
	meta:
		description = "VirTool:Win32/Injector.gen!EI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 52 19 8b 1d 90 01 04 02 53 02 30 14 08 8b 15 90 01 04 0f b6 52 02 41 03 d6 3b ca 76 90 00 } //01 00 
		$a_01_1 = {8a 01 84 c0 74 3a 32 45 77 2a 45 70 fe c8 88 04 } //01 00 
		$a_01_2 = {74 09 b8 00 20 00 00 66 09 47 16 8d 45 f8 50 ff 77 54 } //01 00 
		$a_01_3 = {8b 00 05 00 10 00 00 8b 48 fc 32 cd 80 f9 10 75 f1 } //00 00 
	condition:
		any of ($a_*)
 
}