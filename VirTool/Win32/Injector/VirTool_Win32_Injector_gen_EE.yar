
rule VirTool_Win32_Injector_gen_EE{
	meta:
		description = "VirTool:Win32/Injector.gen!EE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {74 00 66 c7 45 90 03 01 01 f0 f4 2e 00 8b 90 03 01 01 41 43 28 90 09 0d 00 66 c7 45 90 03 01 01 ee f2 90 00 } //01 00 
		$a_03_1 = {74 08 8d 85 90 01 02 ff ff ff d0 90 00 } //01 00 
		$a_03_2 = {83 c0 01 89 45 90 01 01 81 7d 90 1b 00 80 0f 00 00 0f 85 90 01 02 ff ff 90 02 60 ff 90 03 04 04 55 90 01 01 95 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}