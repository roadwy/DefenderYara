
rule Trojan_Win32_Glupteba_RDV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 0c 24 83 c4 04 81 c2 00 a8 6a 38 e8 90 01 04 81 eb 29 d2 30 61 81 c2 c0 41 f4 c9 81 ea 01 00 00 00 31 0f 09 da 81 c2 64 93 88 9e 47 21 da 39 f7 75 90 00 } //01 00 
		$a_02_1 = {83 ec 04 c7 04 24 90 01 04 5a 81 c0 ae 69 2a df 09 db e8 90 01 04 81 c3 48 e9 a8 c9 31 16 81 c3 7b 2d b5 54 01 c3 21 d8 81 c6 90 01 04 81 eb df fb d1 45 01 c0 89 c0 39 fe 75 90 00 } //01 00 
		$a_02_2 = {59 57 58 09 c7 e8 90 01 04 29 f8 01 ff 68 90 01 04 5f 31 0e 09 c0 46 81 ef 01 00 00 00 57 58 39 d6 75 90 00 } //01 00 
		$a_02_3 = {21 c0 81 eb 01 00 00 00 e8 90 01 04 b8 c4 9c da 43 09 c0 31 3e 89 c3 89 c3 4b 81 c6 01 00 00 00 89 c0 29 db 39 ce 75 90 00 } //01 00 
		$a_02_4 = {5f 01 d2 e8 90 01 04 4a 81 e8 74 d8 a7 d7 31 3b 81 e8 c8 b3 4f 47 43 68 90 01 04 58 29 c0 39 f3 75 90 00 } //01 00 
		$a_02_5 = {be ec d5 b7 68 e8 90 01 04 4e 29 c0 89 f0 31 3b 81 c6 63 40 72 ff 46 43 89 c6 21 f0 39 d3 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}