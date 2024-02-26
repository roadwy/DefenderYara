
rule Trojan_Win32_Pikabot_AD_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {8a 84 3d f8 fe ff ff 88 8c 3d f8 fe ff ff 88 84 35 f8 fe ff ff 0f b6 8c 3d f8 fe ff ff 0f b6 c0 03 c8 0f b6 c1 8a 84 05 f8 fe ff ff 32 04 13 88 02 42 83 6d fc 01 75 } //00 00 
		$a_00_2 = {5d 04 00 00 93 44 06 80 5c 31 00 00 94 44 06 80 00 00 01 00 06 00 1b 00 42 61 63 6b 64 6f 6f 72 3a 57 69 6e 36 34 2f 48 61 76 6f 63 2e 41 44 21 4d 54 42 00 00 01 40 05 82 42 00 04 00 78 47 00 00 65 00 65 00 02 00 00 01 00 0a 01 f1 d5 00 fa 4c 62 cc f4 0f 0b 64 00 2a 03 41 83 e9 20 6b c0 21 45 0f b6 } //c9 49 
	condition:
		any of ($a_*)
 
}