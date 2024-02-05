
rule Worm_Win32_Pondfull_B{
	meta:
		description = "Worm:Win32/Pondfull.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_13_0 = {c9 31 04 0b 05 90 01 04 83 c1 04 81 f9 90 01 03 00 75 ed eb 05 e8 de ff ff ff 90 00 01 } //00 2d 
		$a_5e_1 = {d6 00 00 80 7c 00 00 dd 77 00 00 ab 71 00 00 41 7e 00 00 } //00 00 
		$a_01_5 = {03 7c 90 01 03 7c 90 00 01 00 31 13 5a 03 d0 c7 02 2e 65 78 65 c6 42 04 00 8d 94 24 00 01 00 00 6a 03 6a 01 68 00 00 00 10 52 e8 90 01 04 83 c4 90 01 01 83 f8 00 74 90 01 01 50 90 00 00 00 87 10 00 00 d5 3c 2f 6d 94 3e 81 87 d5 dc b4 ad ed 0a 00 00 5d 04 00 00 b5 1d 03 80 5c 22 00 00 b6 1d 03 80 00 00 01 00 05 00 0c 00 a4 21 47 61 6d 61 72 75 65 2e 41 4d 00 00 2e 40 05 82 64 00 04 00 67 16 00 00 80 fb 85 07 aa 8c 37 de 6e 5c 79 } //1e 00 
	condition:
		any of ($a_*)
 
}