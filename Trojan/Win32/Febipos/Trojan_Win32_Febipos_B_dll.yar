
rule Trojan_Win32_Febipos_B_dll{
	meta:
		description = "Trojan:Win32/Febipos.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {39 5f 04 75 19 c7 45 fc ff ff ff ff 39 75 e4 0f 82 b2 01 00 00 8b 4d d0 51 e9 a1 01 00 00 c6 45 fc 01 8b 47 04 8b 10 8b 52 48 8d 4d bc 51 50 ff d2 3b c3 74 0f c7 } //1
		$a_01_1 = {7b 00 33 00 35 00 34 00 33 00 36 00 31 00 39 00 43 00 2d 00 44 00 35 00 36 00 33 00 2d 00 34 00 33 00 66 00 37 00 2d 00 39 00 35 00 45 00 41 00 2d 00 34 00 44 00 41 00 37 00 45 00 31 00 43 00 43 00 33 00 39 00 36 00 41 00 7d 00 } //1 {3543619C-D563-43f7-95EA-4DA7E1CC396A}
		$a_01_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 50 00 6c 00 75 00 67 00 69 00 6e 00 } //1 MicrosoftSecurityPlugin
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 73 75 70 62 72 2e 69 6e 66 6f 2f 73 71 6c 76 61 72 62 72 2e 70 68 70 } //2 https://supbr.info/sqlvarbr.php
		$a_03_4 = {89 5d fc 8b 45 d0 be 08 00 00 00 39 75 e4 73 03 8d 45 d0 68 ?? ?? ?? ?? 68 78 dc 00 10 50 e8 ?? ?? ?? ?? 83 c4 0c 89 5d cc 39 5d e0 75 12 be 13 00 00 00 8d 45 d0 } //2
		$a_01_5 = {62 65 67 69 6e 49 74 28 29 3b } //1 beginIt();
		$a_01_6 = {ff d3 85 c0 0f 85 7e 00 00 00 8d 85 fc f7 ff ff 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 8b 95 f8 f7 ff ff d1 f8 8d 44 00 02 50 8d 8d fc f7 ff ff 51 6a 01 6a 00 6a 00 52 ff d6 8b 85 f8 f7 ff ff 6a 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}