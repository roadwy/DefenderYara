
rule Trojan_Win32_Zbot_DAL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 21 c5 6e 64 07 8c 1d 98 0f ad 62 a6 1f 7b 13 b8 fa 6a 5e 7e e7 42 b5 e4 89 b2 ac 89 96 dc 5c f8 96 b3 80 ab 9c 2e 5c ea 24 48 1c 1c f2 a1 bd 86 84 } //01 00 
		$a_01_1 = {1c 1a 74 09 3a 8c 21 4f 0c 0a 33 20 b1 0b 22 6f df 22 45 ce 38 a9 7c 40 20 6f 3d 33 ac 99 47 86 44 53 2c 20 45 0a 22 4b } //01 00 
		$a_01_2 = {10 31 eb de c0 b1 43 20 6c e0 62 27 e8 86 60 90 c8 70 a9 20 1b 7d 3e 6b 02 83 77 4b 75 9c 65 38 a0 86 2a b4 c4 80 e6 3c be 03 93 87 9b ee b8 6d 98 a8 59 a3 90 72 54 } //01 00 
		$a_01_3 = {95 1c 9e 5e 31 24 47 40 38 37 2d 63 44 35 fc ff b9 b1 be a7 ce c4 22 ec 28 8a 4c f2 f8 cf 9f 12 3c 04 d1 ee ec bb d0 14 5c 33 d3 8e e7 4b 34 93 f2 d7 7b 4d 01 2b 93 a3 b7 } //01 00 
		$a_01_4 = {8a cf 40 a8 0f 92 1a 5f 45 d0 da 19 a0 ad 60 2d 7c 56 0a 54 ef b6 9d 81 29 90 b5 43 06 98 94 3c dc c9 23 0c 5c 08 e2 57 98 ad 10 53 cc b6 4e 74 3a 13 f6 a2 0b c9 13 } //00 00 
	condition:
		any of ($a_*)
 
}