
rule Trojan_Win32_Straftoz_A{
	meta:
		description = "Trojan:Win32/Straftoz.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {7d 28 0f b7 45 f8 8b 4d fc 8b 49 04 0f be 04 01 8b 4d fc 0f b6 09 33 c1 0f b7 4d f8 33 c1 0f b7 4d f8 8b 55 0c 88 04 0a eb bd } //01 00 
		$a_01_1 = {c7 85 90 fe ff ff 0e dd 66 fc c7 85 84 fe ff ff b7 77 00 00 ff b5 84 fe ff ff ff b5 90 fe ff ff e8 } //01 00 
		$a_01_2 = {8b 4d f0 81 e1 d5 fd 00 00 2b c1 89 85 b4 fe ff ff c7 85 d0 fe ff ff d6 6b 00 00 8d 85 d0 fe ff ff } //01 00 
		$a_01_3 = {70 02 00 00 0f 8c ff 00 00 00 83 65 f8 00 eb 07 8b 45 f8 40 89 45 f8 81 7d f8 e3 00 00 00 7d 4c } //01 00 
		$a_01_4 = {eb 0c 66 8b 45 f8 66 83 c0 01 66 89 45 f8 0f b7 45 f8 8b 4d fc 0f b7 49 02 3b c1 7d 2e } //01 00 
		$a_01_5 = {c7 45 e0 40 be 55 f1 c7 45 f4 35 00 00 00 c7 45 c8 8a 00 00 00 81 7d c8 a4 94 00 00 75 16 } //00 00 
		$a_00_6 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}