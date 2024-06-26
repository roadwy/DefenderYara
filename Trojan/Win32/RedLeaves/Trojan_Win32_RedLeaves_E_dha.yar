
rule Trojan_Win32_RedLeaves_E_dha{
	meta:
		description = "Trojan:Win32/RedLeaves.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4b 04 3b 4b 08 75 4c 83 fa 20 73 1e bb 00 00 00 80 8b ca d3 eb 8d 4c 02 04 f7 d3 21 5c b8 44 fe 09 75 28 8b 4d 08 21 19 eb 21 8d 4a e0 bb 00 00 00 80 d3 eb 8d 4c 02 04 f7 d3 21 9c b8 c4 00 00 00 fe 09 75 06 8b 4d 08 21 59 04 8b 4d fc 8b 5d 0c eb 03 } //0a 00 
		$a_03_1 = {55 8b ec 51 56 57 33 c0 b1 90 01 01 8a 90 01 05 32 d1 88 90 01 05 40 3d 90 01 03 00 7c ea 6a 40 68 00 10 00 00 68 90 01 03 00 6a 00 ff 15 90 01 04 85 c0 89 45 fc 75 08 5f 5e 8b e5 5d c2 04 00 b9 90 01 03 00 be 90 01 04 8b f8 f3 a5 90 02 09 8b 90 01 01 fc 90 01 02 ff d0 5f b8 01 00 00 00 5e 8b e5 5d c2 04 00 90 00 } //0a 00 
		$a_03_2 = {c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 90 01 04 73 17 8b 4d f8 8a 91 90 01 04 80 f2 40 8b 45 f8 88 90 90 90 01 04 eb d7 6a 40 68 00 10 00 00 68 90 01 04 6a 00 ff 15 90 01 04 89 45 fc 83 7d fc 00 75 04 33 c0 eb 32 68 90 01 04 68 90 01 04 8b 4d fc 51 e8 90 01 04 83 c4 0c 68 90 01 04 6a 00 68 90 01 04 e8 90 01 04 83 c4 0c c1 c8 07 8b 45 fc ff d0 5f 5e 5b 8b e5 5d c3 90 00 } //01 00 
		$a_03_3 = {57 8b 56 10 83 fa ff 0f 84 9f 00 00 00 8b 7e 08 8d 8e 18 20 00 00 8b c7 2b c6 83 e8 18 c1 f8 03 c1 e0 0c 03 c2 3b f9 89 45 fc 73 3a 8b 0f 8b 5d 08 3b cb 7c 1a 39 5f 04 76 15 53 51 50 e8 90 01 04 83 c4 0c 85 c0 75 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}