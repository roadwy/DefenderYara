
rule Adware_MacOS_Pirrit_N_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.N!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b 68 04 48 89 df e8 90 01 03 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 90 00 } //01 00 
		$a_00_1 = {48 8d 35 46 1e 01 00 e8 8d f9 00 00 48 8b 05 46 33 01 00 48 83 c0 10 48 89 03 48 83 c4 08 } //01 00 
		$a_00_2 = {48 8d bd b0 d7 ff ff 48 8d b5 e0 d6 ff ff 31 d2 e8 7c 84 00 00 48 8d bd b0 d7 ff ff e8 5c 8b 00 00 48 8d bd e0 d6 ff ff e8 0a 98 00 00 4c 89 ef e8 dc 43 00 00 48 85 c0 75 1e 48 8b 85 a0 d4 ff ff 48 8b 40 e8 48 8d bc 05 a0 d4 ff ff 8b 77 20 } //00 00 
	condition:
		any of ($a_*)
 
}