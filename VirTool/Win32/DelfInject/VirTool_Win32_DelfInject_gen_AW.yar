
rule VirTool_Win32_DelfInject_gen_AW{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 61 63 6b 65 64 20 77 69 74 68 20 62 6f 74 43 72 79 70 74 65 72 20 76 90 05 04 04 2e 30 2d 39 20 62 79 20 53 57 69 4d 00 90 00 } //02 00 
		$a_03_1 = {6a 04 68 00 30 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 01 01 8b 40 34 50 8b 45 90 01 01 50 a1 90 01 04 8b 00 ff d0 90 00 } //01 00 
		$a_03_2 = {0f b7 40 06 2b c7 2b c6 72 90 01 01 40 89 45 d8 8d 45 ec 50 8d 3c b6 8b 45 e0 8b 44 f8 10 90 00 } //01 00 
		$a_03_3 = {e4 bb 01 00 00 00 8b 45 f8 0f b6 44 18 ff 99 f7 fb 33 f2 43 ff 4d 90 01 01 75 ed 81 fe ff 00 00 00 7e 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}