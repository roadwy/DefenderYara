
rule Trojan_Win32_Meralifea_A_dll{
	meta:
		description = "Trojan:Win32/Meralifea.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 46 07 84 c0 74 90 01 01 8b 4c 24 18 8b 46 20 85 c9 74 02 89 01 a8 07 74 0a c1 e8 03 8d 04 c5 08 00 00 00 8d 4e 10 90 00 } //01 00 
		$a_01_1 = {8b c1 8d 14 39 83 e0 07 8a 1c 2a 8a 44 30 08 32 c3 41 88 02 8b 46 10 3b c8 72 e5 } //03 00 
		$a_03_2 = {89 29 8b 4e 10 3b c1 72 e6 5d 8b 54 24 1c a1 90 01 04 56 52 50 ff d7 90 00 } //02 00 
		$a_00_3 = {00 43 50 41 49 4c 6f 61 64 00 } //02 00  䌀䅐䱉慯d
		$a_00_4 = {00 44 6c 6c 49 6e 73 74 61 6c 6c 20 3d 3d 3e 0a 00 } //00 00 
		$a_00_5 = {5d 04 00 00 3f } //bc 03 
	condition:
		any of ($a_*)
 
}