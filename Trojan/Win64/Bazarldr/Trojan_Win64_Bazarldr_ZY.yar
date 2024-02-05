
rule Trojan_Win64_Bazarldr_ZY{
	meta:
		description = "Trojan:Win64/Bazarldr.ZY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 8b 01 b8 ff ff ff ff 4d 03 c3 41 0f b6 08 85 c9 0f 84 a2 00 00 00 66 0f 1f 84 00 00 00 00 00 33 c1 4d 8d 40 01 8b d0 8b c8 c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 } //01 00 
		$a_01_1 = {c1 e2 1f c1 fa 1f 81 e2 96 30 07 77 33 d1 8b c8 c1 e1 19 c1 f9 1f 81 e1 90 41 dc 76 33 d1 8b c8 c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 d1 8b c8 c1 e1 1b c1 f9 1f } //01 00 
		$a_01_2 = {81 e1 64 10 b7 1d 33 d1 8b c8 c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 d1 8b c8 c1 e9 08 33 d1 8b c8 c1 e1 18 c1 f9 1f 81 e1 20 83 b8 ed c1 e0 1e 33 d1 c1 f8 1f 8b c8 8b c2 } //01 00 
		$a_01_3 = {81 e1 2c 61 0e ee 33 c1 41 0f b6 08 85 c9 0f 85 67 ff ff ff f7 d0 3b c7 74 27 41 ff c2 49 83 c1 04 44 3b d3 0f 82 31 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}