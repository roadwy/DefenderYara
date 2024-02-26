
rule Trojan_Win32_Qukart_ASQ_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b fe bc 8a d8 57 14 8a 99 6d 94 37 ac 95 4e b9 ac 7d c7 b1 a4 82 71 65 7c 3f 44 9d 48 b6 44 75 2f b9 40 cd ad 7d 44 75 } //05 00 
		$a_01_1 = {3d 27 33 8b b2 52 b7 8c b5 04 48 83 31 21 44 f5 b2 d0 c7 87 31 d8 35 d5 64 21 23 93 ba e9 a4 08 31 27 48 20 01 7c } //05 00 
		$a_01_2 = {ad 37 2a e8 b1 1b 81 13 e5 90 f4 9c 9d 33 31 17 cd 37 7e 79 64 27 7c } //05 00 
		$a_01_3 = {1b 52 53 e6 61 68 c5 18 9e 38 2d f1 98 5a ad 19 1d fc 8d 90 1b 5c 53 e6 61 31 6d 6d 82 50 ad 18 } //05 00 
		$a_01_4 = {28 11 c9 d1 ab 63 4a d9 59 31 1f 20 4f 77 c1 e8 c8 ec 4a 26 24 c4 7a } //00 00 
	condition:
		any of ($a_*)
 
}