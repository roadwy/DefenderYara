
rule Trojan_Win32_Plugx_D{
	meta:
		description = "Trojan:Win32/Plugx.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 3c 85 00 00 00 00 bb fd ff ff ff 2b df 03 c3 8b f9 c1 e7 04 8d 4c 0f 05 8b fa c1 e7 06 bb f9 ff ff ff 2b df 8b 7c 24 14 03 d3 8b 5c 24 1c 69 db 01 01 00 00 83 c3 09 89 5c 24 1c 02 da 02 d9 02 d8 30 1c 3e 46 3b f5 72 b6 } //01 00 
		$a_01_1 = {8a 08 40 84 c9 75 f9 2b c2 83 c0 fc 3b c6 76 16 50 8d 54 24 70 52 8d 84 24 78 01 00 00 50 e8 } //01 00 
		$a_01_2 = {ff d7 8b 4c 24 0c 8a 54 24 10 89 0e 8d 44 24 08 50 88 56 04 8b 4c 24 0c 51 6a 05 56 ff d7 5f } //01 00 
		$a_01_3 = {83 e8 05 88 5c 24 11 88 5c 24 12 88 5c 24 13 88 5c 24 14 89 44 24 11 8d 44 24 0c 50 6a 04 6a 05 56 c6 44 24 20 e9 89 35 } //00 00 
		$a_00_4 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}