
rule VirTool_Win32_Injector_gen_EU{
	meta:
		description = "VirTool:Win32/Injector.gen!EU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {69 c9 9b cf 62 00 2b c1 2d dc 25 d7 02 89 45 90 01 01 8b 55 90 01 01 33 c0 90 03 08 05 8b 4d 90 01 01 8a 42 10 8a 42 10 8b 4d 90 00 } //01 00 
		$a_03_1 = {b9 30 00 00 00 33 c0 8d bd 90 01 04 f3 ab 66 ab c7 45 fc 90 01 04 8b 55 fc 52 90 09 0e 00 66 8b 0d 90 01 04 66 89 8d 90 00 } //01 00 
		$a_02_2 = {00 59 41 70 70 2e 45 58 45 90 05 01 02 5c 2f 00 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}