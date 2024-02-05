
rule Trojan_MacOS_Niqtana_B_xp{
	meta:
		description = "Trojan:MacOS/Niqtana.B!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 73 77 69 74 63 68 65 72 6f 6f } //01 00 
		$a_00_1 = {53 77 69 74 63 68 69 6e 67 20 61 72 63 68 20 74 79 70 65 73 20 74 6f 20 65 78 65 63 75 74 65 20 6f 75 72 20 70 61 72 61 73 69 74 65 } //01 00 
		$a_00_2 = {8b 45 e4 89 44 24 08 8d 85 e4 fe ff ff 89 44 24 04 8b 45 08 89 04 24 e8 3e 17 00 00 3b 45 e4 74 0c c7 85 d4 fe ff ff ff ff ff ff eb 39 81 7d e4 00 01 00 00 75 26 c7 44 24 08 00 01 00 00 8d 85 e4 fe ff ff 89 44 24 04 8b 45 0c 89 04 24 e8 02 17 00 00 89 45 e4 83 7d e4 00 75 a4 } //01 00 
		$a_00_3 = {89 f9 31 d1 31 f0 09 c8 85 c0 74 09 c7 45 e4 ff ff ff ff eb 36 c7 45 f0 ef be ad de c7 44 24 08 04 00 00 00 8d 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 fb 17 00 00 83 f8 04 74 09 c7 45 e4 ff ff ff ff eb 07 c7 45 e4 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}