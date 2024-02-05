
rule Ransom_Win32_Dircrypt_gen_A{
	meta:
		description = "Ransom:Win32/Dircrypt.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 02 00 00 00 a4 00 00 52 53 41 31 00 04 00 00 01 00 01 00 3b 45 6c cf a9 fb 55 3e 63 c9 7e c1 1c 8d d2 31 a6 c4 b0 33 41 bc a4 2f d5 c5 03 50 74 91 8c 5b 3e c7 47 0e ca ff 1e 5b 36 6c 27 83 f6 4c 29 24 f3 37 67 18 91 bb 6b cf 21 55 ec a1 6e 92 5a 02 2d 81 75 f2 58 5e 2b bf 17 25 5f 8e 1c a6 de 39 ab 93 b5 d4 88 04 02 3b ea bd 0b e3 35 9a 0f 33 a2 c6 17 b1 40 9f f6 bc 34 1a 09 16 13 2e 87 a6 d7 23 75 37 b5 8d 3b 54 7b 6c 69 6c 23 c4 fd b0 } //01 00 
		$a_01_1 = {06 02 00 00 00 24 00 00 52 53 41 31 00 04 00 00 01 00 01 00 73 9a e6 c6 d2 c2 1e 86 e3 3a 60 16 d1 6a b3 a3 58 21 de 3d 4e c1 2c a9 d0 8a be 4d 1c 4f 3c ae 32 8a 3f 03 59 1d 24 49 c4 54 0f c5 53 09 88 95 bd 5f ea d4 4a 17 29 59 41 00 54 85 41 d9 8f e2 07 cb 7f 37 8d fe 8c b7 5a 90 02 88 09 89 9e 77 10 8f 71 d7 26 08 82 63 83 2e a0 d9 bd 48 c1 e2 01 51 6b 35 a0 53 8b ab 98 11 28 e1 38 84 24 13 82 a5 2c b1 04 dd 95 a1 27 ce 75 89 7f 7d 7c 97 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}