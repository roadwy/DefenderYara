
rule Ransom_Win32_GandCrab_AE_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {e4 e7 ad 7a c7 90 01 03 e5 2e cd 5b c7 90 01 03 9a dc a0 75 81 90 01 03 ad 7d d8 77 81 90 01 03 eb 57 f8 5e 81 90 01 03 0e 1a 61 2a 81 90 01 03 b4 c8 b9 65 81 90 01 03 0a 73 d7 07 81 90 01 03 ca bb e3 2a a1 90 01 04 a3 90 01 04 ff d0 90 00 } //01 00 
		$a_02_1 = {e4 e7 ad 7a c7 90 01 02 e5 2e cd 5b c7 90 01 02 9a dc a0 75 81 90 01 02 ad 7d d8 77 81 90 01 02 eb 57 f8 5e 81 90 01 02 0e 1a 61 2a 81 90 01 02 b4 c8 b9 65 81 90 01 02 0a 73 d7 07 81 90 01 02 ca bb e3 2a a1 90 01 04 a3 90 01 04 ff d0 90 00 } //01 00 
		$a_02_2 = {e4 e7 ad 7a c7 90 01 02 e5 2e cd 5b c7 90 01 02 9a dc a0 75 c7 90 01 02 0e a2 2e 55 81 90 01 02 ad 7d d8 77 81 90 01 02 eb 57 f8 5e 81 90 01 02 0e 1a 61 2a 81 90 01 02 b4 c8 b9 65 81 90 01 02 0a 73 d7 07 81 90 01 02 ca bb e3 2a a1 90 01 04 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}