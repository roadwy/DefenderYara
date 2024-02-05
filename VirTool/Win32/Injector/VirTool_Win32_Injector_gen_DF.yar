
rule VirTool_Win32_Injector_gen_DF{
	meta:
		description = "VirTool:Win32/Injector.gen!DF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 00 3c 2a 74 06 33 f6 eb b3 eb 03 46 eb ae } //01 00 
		$a_01_1 = {c7 00 57 72 69 74 c7 40 04 65 50 72 6f c7 40 08 63 65 73 73 c7 40 0c 4d 65 6d 6f c7 40 10 72 79 00 00 } //01 00 
		$a_03_2 = {89 03 83 c6 04 8b 5d 90 01 01 03 de 8b 85 90 01 04 89 03 83 c6 04 3b 75 90 01 01 73 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}