
rule Adware_MacOS_Pirrit_L_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.L!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b 68 04 48 89 df e8 90 01 03 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 90 00 } //01 00 
		$a_00_1 = {80 35 db 9e 11 00 24 80 35 d5 9e 11 00 06 80 35 cf 9e 11 00 f3 80 35 c9 9e 11 00 b3 80 35 c3 9e 11 00 3f 80 35 bd 9e 11 00 a0 80 35 b7 9e 11 00 68 80 35 b1 9e 11 00 90 80 35 ab 9e 11 00 d1 80 35 a5 9e 11 00 18 b0 e1 30 05 9e 9e 11 00 80 35 98 9e 11 00 17 80 35 92 9e 11 00 9f 80 35 8c 9e 11 00 64 80 35 86 9e 11 00 b8 80 35 65 9e 11 00 55 30 05 60 9e 11 00 80 35 5a 9e 11 00 dc 80 35 54 9e 11 00 41 ff 25 2f a4 11 00 } //01 00 
		$a_00_2 = {f2 0f 11 45 d0 48 8d 3d 27 99 11 00 ff d3 48 89 c3 48 8d 3d 27 99 11 00 41 ff d6 49 89 c6 48 8d 15 b2 6c 11 00 48 8d 0d 7b 99 11 00 48 89 df 48 89 c6 45 31 c0 31 c0 41 ff d7 48 8b 05 36 9f 11 00 } //00 00 
	condition:
		any of ($a_*)
 
}