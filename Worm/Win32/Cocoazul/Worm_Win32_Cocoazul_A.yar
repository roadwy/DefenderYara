
rule Worm_Win32_Cocoazul_A{
	meta:
		description = "Worm:Win32/Cocoazul.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 08 40 84 c9 75 f9 2b c6 3d 00 8c 01 00 76 49 6a 03 5f ff 75 90 01 01 be 90 01 04 68 90 01 04 e8 90 01 02 ff ff 4f 85 c0 74 0a 85 ff 75 e5 ff 85 20 07 00 00 8b 55 90 01 01 33 c0 8b fa b9 ff 63 00 00 f3 ab 66 ab aa 90 00 } //01 00 
		$a_02_1 = {c7 45 fc 5b 57 5d 00 eb 37 e8 90 01 02 ff ff e8 90 01 02 ff ff c7 45 fc 5b 4d 5d 00 eb 24 e8 90 01 02 ff ff e8 90 01 02 ff ff c7 45 fc 5b 52 5d 00 eb 11 e8 90 01 02 ff ff e8 90 01 02 ff ff c7 45 fc 5b 4c 5d 00 90 00 } //01 00 
		$a_02_2 = {85 c0 74 0b 48 80 bc 05 90 01 02 00 00 5c 75 f1 8d bc 05 90 01 02 00 00 be 90 01 04 a5 a5 a5 8d 85 90 01 02 00 00 50 66 a5 ff 15 90 01 04 8d 45 90 01 01 50 68 90 01 04 ff 15 90 01 04 8b f0 83 fe ff 74 1f 83 7d 90 01 01 20 90 00 } //01 00 
		$a_02_3 = {fe 45 0b 8b 75 e4 8b 45 f4 ff 45 f8 03 c0 83 7d f8 1a 89 45 f4 0f 8c da fe ff ff 5f 8b c6 5e 5b c9 c2 04 00 be 90 01 04 a5 a5 66 a5 eb d1 be 90 01 04 a5 a5 a5 eb c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}