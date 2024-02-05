
rule Worm_Win32_Fluteytu_A{
	meta:
		description = "Worm:Win32/Fluteytu.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 ff 42 c7 45 f8 90 01 04 8d 45 f4 8a 55 ff e8 90 01 04 8d 45 f4 ba 90 01 04 e8 90 01 04 8b 45 f4 e8 90 01 04 50 e8 90 01 04 83 f8 02 0f 85 90 00 } //01 00 
		$a_01_1 = {80 fb 41 72 2a 80 fb 5b 77 25 6a 14 e8 } //01 00 
		$a_03_2 = {80 38 2e 0f 84 90 01 02 ff ff ba 07 00 00 00 8b 45 fc e8 90 01 04 8d 45 fc ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}