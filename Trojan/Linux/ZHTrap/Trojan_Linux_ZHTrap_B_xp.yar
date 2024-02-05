
rule Trojan_Linux_ZHTrap_B_xp{
	meta:
		description = "Trojan:Linux/ZHTrap.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 73 66 6b 6a 64 6b 66 64 6a 2e 74 78 74 } //01 00 
		$a_00_1 = {5a 6f 6e 65 53 65 63 } //01 00 
		$a_00_2 = {51 6a 66 6a 78 53 52 44 46 47 53 46 44 64 66 } //01 00 
		$a_00_3 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //01 00 
		$a_00_4 = {30 78 64 65 61 64 62 65 65 66 2e 74 77 } //01 00 
		$a_00_5 = {0f be ca ba 81 80 80 80 89 c8 f7 ea 89 c8 c1 f8 1f 01 ca c1 fa 07 29 c2 89 d0 c1 e0 08 29 d0 89 f2 29 c1 46 8b 44 24 28 30 cb 00 54 24 27 32 5c 24 26 32 5c 24 27 39 74 24 14 88 1c 28 74 21 8b 44 24 20 89 74 24 28 0f b6 1c 2e 0f b6 14 07 8d 47 01 31 ff 83 f8 0e c6 44 24 27 00 7f a2 } //00 00 
	condition:
		any of ($a_*)
 
}