
rule Spammer_Win32_Emotet_D{
	meta:
		description = "Spammer:Win32/Emotet.D,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 48 33 d2 8b cf 2b f7 58 8a 1c 0e 32 9a 90 01 04 42 88 19 83 fa 09 72 02 33 d2 41 48 75 e9 90 00 } //0a 00 
		$a_03_1 = {0f b6 cb 8d 3c 31 8a 0f 02 d1 88 54 24 90 01 01 0f b6 d2 8d 2c 32 8a 55 00 88 17 8b 7c 24 90 01 01 88 4d 00 0f b6 d2 0f b6 c9 03 d1 81 e2 ff 00 00 00 0f b6 14 32 30 14 38 40 fe c3 3b 44 24 90 01 01 72 be 90 00 } //0a 00 
		$a_01_2 = {0f b6 00 0f b6 4d ff 0f b6 55 f7 03 ca 81 e1 ff 00 00 00 8b 55 f8 0f b6 0c 0a 33 c1 8b 4d 0c 03 4d f0 88 01 e9 6b ff ff ff } //0a 00 
		$a_01_3 = {8b 45 08 03 45 f8 0f b6 08 8b 55 f4 0f b6 82 10 00 54 00 33 c8 8b 55 fc 03 55 f8 88 0a 8b 45 f4 83 c0 01 89 45 f4 83 7d f4 09 72 07 c7 45 f4 00 00 00 00 } //0a 00 
		$a_03_4 = {03 c1 25 ff 00 00 00 8b 4d 90 01 01 0f b6 04 01 33 d0 8b 4d 0c 03 4d 90 01 01 88 11 e9 90 00 } //0a 00 
		$a_01_5 = {22 00 25 00 73 00 22 00 20 00 2f 00 63 00 20 00 22 00 25 00 73 00 22 00 } //0a 00  "%s" /c "%s"
		$a_01_6 = {43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 } //01 00  ComSpec
		$a_01_7 = {25 66 72 6f 6d 5f 65 6d 61 69 6c 25 } //00 00  %from_email%
		$a_00_8 = {7e 15 00 00 46 61 97 61 de e6 c6 8e d8 3d 64 c5 d5 3c 84 2d } //00 00 
	condition:
		any of ($a_*)
 
}