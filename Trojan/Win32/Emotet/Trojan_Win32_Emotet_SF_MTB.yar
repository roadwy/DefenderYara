
rule Trojan_Win32_Emotet_SF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 00 8b c6 0d 00 02 00 00 81 e1 00 00 00 04 0f 44 c6 8b f0 8d 44 24 28 50 8b 45 e8 56 ff 75 ec 03 c3 50 ff 54 24 3c 85 c0 0f 84 90 01 02 ff ff 8b 44 24 24 83 c5 28 85 c0 0f 85 90 01 02 ff ff 90 00 } //02 00 
		$a_01_1 = {8b d8 33 ff 8b 0b 8d 5b 04 33 4d f4 0f b6 c1 66 89 06 8b c1 c1 e8 08 8d 76 08 0f b6 c0 66 89 46 fa c1 e9 10 0f b6 c1 c1 e9 08 47 66 89 46 fc 0f b6 c1 66 89 46 fe 3b fa 72 ca } //02 00 
		$a_01_2 = {8b 75 fc 8b 0b 8d 5b 04 33 4d f8 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 fd 88 4a fe c1 e9 08 46 88 4a ff 3b f7 72 da } //00 00 
		$a_00_3 = {7e 15 00 00 } //57 b1 
	condition:
		any of ($a_*)
 
}