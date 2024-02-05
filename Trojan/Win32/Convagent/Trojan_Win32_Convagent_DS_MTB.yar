
rule Trojan_Win32_Convagent_DS_MTB{
	meta:
		description = "Trojan:Win32/Convagent.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 d6 8b c5 14 08 84 9e 04 33 5a 5d 5f ee db c2 73 87 6f 5a f8 ba 8b fb 8b 32 4b 7b 7b 7b e1 3b f0 72 0b ce 03 4a 35 e8 03 6b 67 cd 77 62 11 bc 75 6d 7b 75 1b 8b b7 01 1b 05 29 51 83 7b 0c ec b7 83 2d 3b 48 61 eb 3f 2c 8b 7a 04 03 } //01 00 
		$a_01_1 = {13 96 bf 49 04 6a 01 68 00 20 56 bf 80 8b f8 89 3b 85 ff 74 b0 1d 66 f8 23 8b d3 b8 d8 47 63 13 24 80 7c 58 f7 fd e3 8b 03 50 26 88 f8 03 63 55 8b d9 7d 63 bf 37 b3 e8 c7 43 04 60 6a 04 4f 68 0b 55 4d 8e } //01 00 
		$a_01_2 = {85 88 0a c7 05 b4 df 87 f1 72 45 84 10 df 81 fb 58 75 5b 5b 72 db a7 8b 2f 04 75 08 7c 37 bf 19 eb 5a a3 7d 0e 8b 82 4a 79 48 2b 96 80 b1 3d 9c 0d ae ab 14 27 b7 ed 3f d8 f4 b7 8b d0 8b } //01 00 
		$a_01_3 = {13 c1 8d 39 d3 90 3c 10 5e d3 2c a1 1d a5 55 22 2b 49 1d 80 5d cf 89 3d cd b2 b1 83 c6 ec e6 fe be 8b 3c 53 0b 5b 48 ed 63 7d d7 a9 cd a5 0b 1d 71 c7 c7 3b fe f8 b0 01 14 5a ea 6c b5 2f 0a 48 83 ce d6 a6 46 68 38 e7 7b 0a 38 0a 46 07 31 0a 71 5d 7d } //01 00 
		$a_01_4 = {18 17 90 9e c5 27 13 03 35 23 4f fd 71 21 c6 01 36 27 00 25 26 0b f0 89 eb 22 04 6b d9 f8 d4 94 df b0 0c 60 a8 e1 4d 82 c2 a9 0e a2 01 9b da 02 3b c4 7d 0e ad 13 4a b8 d7 9d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Convagent_DS_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.DS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 56 c4 08 00 01 45 fc 8b 15 24 90 48 00 03 55 08 8b 45 fc 03 45 08 8a 08 88 0a } //00 00 
	condition:
		any of ($a_*)
 
}