
rule VirTool_Win32_Afrootix_gen_B{
	meta:
		description = "VirTool:Win32/Afrootix.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 f0 89 03 90 02 02 8b fb 8b d7 83 c2 05 8b 45 f0 e8 90 01 01 00 00 00 83 c7 04 88 07 8b 45 f0 c6 00 e9 8b 45 f0 40 89 30 90 02 02 8d 45 f4 50 8b 45 f4 50 6a 05 8b 45 f0 50 e8 90 01 02 ff ff 83 c3 05 8b 45 fc 89 18 33 c0 5a 59 59 64 89 10 eb 11 90 00 } //01 00 
		$a_02_1 = {8b d0 8b c6 e8 90 01 02 ff ff 89 45 f4 6a 0c 6a 00 8d 4d f0 ba 90 01 02 14 13 8b c6 e8 90 01 02 ff ff 85 c0 74 0f 50 e8 90 01 02 ff ff b3 01 6a 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}