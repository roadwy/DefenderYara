
rule VirTool_Win32_Injector_gen_AP{
	meta:
		description = "VirTool:Win32/Injector.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 1d 30 00 00 00 90 02 20 8b 5b 0c 90 00 } //01 00 
		$a_03_1 = {83 c0 08 50 ff 90 03 04 04 75 90 01 01 b5 90 01 04 ff 15 90 01 04 90 02 20 90 17 08 01 01 01 01 01 01 02 05 50 51 52 53 56 57 6a 00 68 00 00 00 00 ff 90 04 01 06 70 71 72 73 76 77 50 ff 90 03 04 04 75 90 01 01 b5 90 01 04 ff 90 03 04 04 75 90 01 01 b5 90 01 04 ff 90 03 04 04 75 90 01 01 b5 90 01 04 ff 15 90 1b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}