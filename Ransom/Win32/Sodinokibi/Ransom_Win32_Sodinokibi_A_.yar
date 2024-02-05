
rule Ransom_Win32_Sodinokibi_A_{
	meta:
		description = "Ransom:Win32/Sodinokibi.A!!Sodinokibi.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 8a 1c 39 33 d2 0f b6 cb f7 75 10 8b 45 0c 0f b6 04 02 03 c6 03 c8 0f b6 f1 8b 4d fc 8a 04 3e 88 04 39 41 88 1c 3e 89 4d fc 81 f9 00 01 00 00 72 cd } //01 00 
		$a_01_1 = {8b 55 08 40 0f b6 c8 8b 45 08 89 4d 10 8b 5d 10 8a 0c 01 0f b6 c1 03 c6 0f b6 f0 8b 45 08 8a 04 06 88 04 13 8b c2 8b d3 8b 5d 14 88 0c 06 } //01 00 
		$a_01_2 = {0f b6 04 02 8b 55 0c 0f b6 c9 03 c8 0f b6 c1 8b 4d 08 8a 04 08 32 04 1a 88 03 43 8b 45 10 89 5d 14 83 ef 01 75 ac } //00 00 
	condition:
		any of ($a_*)
 
}