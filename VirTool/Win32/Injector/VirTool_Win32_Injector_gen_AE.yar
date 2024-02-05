
rule VirTool_Win32_Injector_gen_AE{
	meta:
		description = "VirTool:Win32/Injector.gen!AE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 90 01 01 33 c9 8a 08 8b 55 0c 03 55 90 01 01 33 c0 8a 02 8b 55 90 01 01 6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 90 01 02 83 7d 10 64 90 00 } //01 00 
		$a_03_1 = {3f e9 d7 21 33 db c7 45 90 01 01 0e a6 09 b7 64 8b 1d 30 00 00 00 c7 45 90 01 01 5e 64 c5 e7 8b 5b 0c 8b 5b 14 c7 45 90 01 01 0b 56 e0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}