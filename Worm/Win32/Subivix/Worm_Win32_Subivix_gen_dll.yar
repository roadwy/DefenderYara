
rule Worm_Win32_Subivix_gen_dll{
	meta:
		description = "Worm:Win32/Subivix.gen!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 42 be 01 00 00 00 8b 45 fc 8a 5c 30 ff 8b c6 25 01 00 00 80 79 05 48 83 c8 fe 40 85 c0 75 05 80 eb 05 eb 03 80 eb 06 8d 45 f4 8b d3 e8 90 01 02 ff ff 8b 55 f4 8b 45 f8 e8 90 01 02 ff ff 8b 45 f8 46 4f 75 c3 90 00 } //01 00 
		$a_00_1 = {6e 79 7a 75 40 34 35 } //00 00 
	condition:
		any of ($a_*)
 
}