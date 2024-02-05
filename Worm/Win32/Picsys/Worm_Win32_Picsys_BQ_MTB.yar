
rule Worm_Win32_Picsys_BQ_MTB{
	meta:
		description = "Worm:Win32/Picsys.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 7b e1 b0 e7 1b 4f 03 56 aa 32 66 09 ba af 6d 0b 74 17 66 7d c0 c5 50 36 80 6d c3 2f c1 c8 58 81 f1 5e ff e1 5e 1a 61 f0 3b 4a fc 42 8b 52 e1 } //01 00 
		$a_01_1 = {71 f9 3f 83 e7 bf 6f f1 e8 02 72 36 c1 eb 52 3d 96 29 11 74 3d 2d 93 df be df b6 2e 22 13 02 24 eb 3a 2d fd 0e 2f 27 3d 74 26 eb 75 ff 0b fd 2c b0 c8 eb 2a b0 } //01 00 
		$a_01_2 = {08 b9 0c 33 c1 9f 53 4c ff d1 8a 37 ff 64 a3 42 7f a0 d8 2c a8 5a 54 55 57 1d 4a c1 c7 56 53 41 07 7b 6c ad 90 8b } //01 00 
		$a_01_3 = {55 50 58 31 00 61 23 a4 00 e0 } //00 00 
	condition:
		any of ($a_*)
 
}