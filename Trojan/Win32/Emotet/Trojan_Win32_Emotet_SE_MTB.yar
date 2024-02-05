
rule Trojan_Win32_Emotet_SE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 33 e2 89 45 90 01 01 81 45 90 01 05 81 45 90 01 05 81 75 90 01 05 8a 4d 90 01 01 8b 7d 90 01 01 0f b7 06 d3 e7 83 f8 41 72 08 83 f8 5a 77 03 83 c0 20 89 45 90 01 01 83 c6 02 01 55 90 01 01 33 c0 01 7d 90 01 01 29 5d 90 01 01 66 39 06 0f 85 90 01 01 ff ff ff 5f 5b 8b 45 90 01 01 5e 8b e5 5d c3 90 00 } //01 00 
		$a_03_1 = {33 c0 8b d6 8d 0c bb 8b f9 2b fb 83 c7 03 c1 ef 02 3b d9 0f 47 f8 85 ff 74 2c 8b 75 90 01 01 8b 0b 8d 5b 04 33 4d 90 01 01 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 90 01 01 88 4a 90 01 01 c1 e9 08 46 88 4a 90 01 01 3b f7 72 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}