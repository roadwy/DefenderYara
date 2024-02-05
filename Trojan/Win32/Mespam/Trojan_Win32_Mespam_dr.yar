
rule Trojan_Win32_Mespam_dr{
	meta:
		description = "Trojan:Win32/Mespam!dr,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 45 00 00 4c 01 02 00 9b 74 e0 45 00 00 00 00 00 00 00 00 e0 00 0f 01 0b 01 06 00 00 22 00 00 00 5c 01 00 00 00 00 00 00 10 00 00 00 10 00 00 00 40 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 b0 01 00 00 04 00 00 00 00 00 00 02 00 00 00 } //01 00 
		$a_01_1 = {55 89 e5 68 2a 02 00 00 50 e8 17 00 00 00 5d eb 43 81 c5 ff 63 fe ff f7 d5 01 dd 89 ef 81 c7 dc 07 00 00 eb 12 92 83 c4 0c 5d eb 52 83 c4 0c 56 53 55 57 31 ed eb d8 e8 4e 00 00 00 85 c9 75 f7 eb 66 e8 03 00 00 00 59 50 c3 59 5e 5b 5d 5f e8 f3 ff ff ff 52 e8 00 00 00 00 5b 66 31 db 8b 13 81 f2 77 44 aa ff 66 81 fa 3a 1e 74 0e 8d 9b 00 f0 00 f5 81 c3 00 f0 af 00 eb e3 5a eb 93 68 aa aa ff 7f 6a 00 e8 a2 ff ff ff ba 08 a4 01 00 8b 04 1a 6a 00 ff d0 8d 88 ae de d7 da 01 4d 00 8d 6c 05 05 89 f9 29 e9 c3 81 ef dc 07 00 00 89 f8 eb 90 } //01 00 
		$a_01_2 = {01 83 88 c1 27 40 00 61 16 b8 07 fd 2d 21 30 85 15 6c 4e 13 32 49 02 d8 99 26 40 00 52 62 a3 23 6e 21 d5 e4 2a fc 28 d3 78 5e 77 75 73 6f 63 41 b7 33 79 62 a1 94 d6 03 2b fc 28 d3 31 f9 02 7a 8a e5 83 ec 5b 96 4c f5 2d 21 d6 03 f2 41 24 d4 31 f9 02 85 8c 75 08 03 c9 0b 16 b4 84 27 20 56 } //00 00 
	condition:
		any of ($a_*)
 
}