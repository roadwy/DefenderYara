
rule TrojanClicker_Win32_Sassrye_A{
	meta:
		description = "TrojanClicker:Win32/Sassrye.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {eb 27 80 3c 1e 7c 75 20 40 c6 04 1e 00 83 f8 01 75 08 03 fe 89 3c 24 8d 7b 01 83 f8 02 75 09 } //02 00 
		$a_03_1 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 00 44 00 00 75 ed 5a 5e 5b c3 90 09 07 00 e8 90 01 04 33 c0 90 00 } //01 00 
		$a_01_2 = {8b d6 83 c2 04 88 02 c6 03 e9 47 89 2f } //01 00 
		$a_00_3 = {5f 53 59 53 54 45 4d 5f 53 45 41 52 43 48 } //00 00 
	condition:
		any of ($a_*)
 
}