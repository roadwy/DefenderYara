
rule Worm_Win32_Comers_A{
	meta:
		description = "Worm:Win32/Comers.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 c6 44 24 90 01 01 6c c6 44 24 90 01 01 6f c6 44 24 90 01 01 72 88 5c 24 90 01 01 c6 44 24 90 01 01 72 c6 44 24 90 01 01 2e 90 00 } //01 00 
		$a_01_1 = {39 44 24 18 75 3c 6a 24 e8 } //01 00 
		$a_01_2 = {8a 06 3c 43 7c 04 3c 5a 7e } //01 00 
		$a_01_3 = {ff d3 8b f0 83 fe ff 74 21 80 bc 24 40 01 00 00 2e } //01 00 
		$a_03_4 = {8b c1 99 f7 fb 8a 04 2a 8a 14 90 01 01 32 d0 88 14 31 41 3b 90 00 } //01 00 
		$a_01_5 = {5c 63 6f 6d 72 65 73 2e 64 6c 6c 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}