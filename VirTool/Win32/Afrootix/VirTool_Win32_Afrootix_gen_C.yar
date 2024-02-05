
rule VirTool_Win32_Afrootix_gen_C{
	meta:
		description = "VirTool:Win32/Afrootix.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 89 1e 90 02 07 8b d6 83 c2 05 8b c3 e8 90 01 01 00 00 00 8b d6 83 c2 04 88 02 c6 03 e9 8b c3 40 89 38 90 02 07 8d 45 f4 50 8b 45 f4 50 6a 05 53 e8 90 01 02 ff ff 83 c6 05 8b 45 fc 89 30 33 c0 5a 59 59 64 89 10 eb 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}