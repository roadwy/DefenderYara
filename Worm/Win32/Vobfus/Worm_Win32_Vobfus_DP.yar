
rule Worm_Win32_Vobfus_DP{
	meta:
		description = "Worm:Win32/Vobfus.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 8b 45 90 01 01 8b 40 90 01 01 03 c8 ff 15 90 01 04 8d 4d 90 01 01 51 8b 15 90 01 04 52 a1 90 01 04 50 e8 90 01 04 8d 4d 90 01 01 51 6a 00 ff 15 90 00 } //01 00 
		$a_03_1 = {c1 e0 04 8b 4d 90 01 01 8b 49 90 01 01 03 c8 ff 15 90 01 04 8d 55 90 01 01 52 a1 90 01 04 50 8b 0d 90 01 04 51 e8 90 01 04 89 85 90 01 04 8d 55 90 01 01 52 6a 00 ff 15 90 01 04 8b 85 90 01 04 89 45 90 00 } //01 00 
		$a_03_2 = {b8 05 00 00 00 2b 41 90 01 01 c1 e0 04 8b 4d 90 01 01 8b 49 90 01 01 03 c8 ff 15 90 01 04 8d 55 90 01 01 52 a1 90 01 04 50 8b 0d 90 01 04 51 e8 90 01 04 8d 55 90 01 01 52 6a 00 ff 15 90 00 } //01 00 
		$a_02_3 = {50 8d 45 e8 50 ff 15 90 01 04 8b f0 68 90 01 04 56 8b 0e ff 91 90 01 04 3b c7 db e2 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}