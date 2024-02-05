
rule Ransom_Win32_Sodinokibi_B_{
	meta:
		description = "Ransom:Win32/Sodinokibi.B!!Sodinokibi.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 06 4a 6a 08 33 c8 46 5f 8b c1 d1 e9 83 e0 01 f7 d0 40 25 20 83 b8 ed 33 c8 83 ef 01 75 ea 85 d2 75 dc } //01 00 
		$a_01_1 = {8b 55 08 6a 2b 58 eb 0c 69 c0 0f 01 00 00 42 0f b6 c9 03 c1 8a 0a 84 c9 75 ee } //01 00 
		$a_01_2 = {05 02 00 00 80 33 c9 53 0f a2 8b f3 5b 8d 5d e8 89 03 8b 45 fc 89 73 04 40 89 4b 08 8b f3 89 53 0c 89 45 fc a5 a5 a5 a5 8b 7d f8 83 c7 10 89 7d f8 83 f8 03 7c ca } //00 00 
	condition:
		any of ($a_*)
 
}