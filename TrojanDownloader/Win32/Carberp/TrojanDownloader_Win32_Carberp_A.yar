
rule TrojanDownloader_Win32_Carberp_A{
	meta:
		description = "TrojanDownloader:Win32/Carberp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 09 00 00 "
		
	strings :
		$a_01_0 = {8a 45 fc f6 eb 02 c2 30 01 43 8a 14 33 84 d2 75 ef } //1
		$a_03_1 = {ac 84 c0 74 09 2c 90 01 01 34 90 01 01 04 90 01 01 aa eb f2 aa 90 00 } //1
		$a_03_2 = {8b 40 28 59 85 c0 74 90 01 01 03 c3 74 0d 6a 00 33 90 03 03 03 f6 46 56 ff 47 57 53 ff d0 90 00 } //1
		$a_03_3 = {68 35 bf a0 be 6a 01 6a 00 e8 90 01 02 ff ff 83 c4 0c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0 90 00 } //1
		$a_03_4 = {68 b3 74 18 e6 6a 01 6a 00 e8 90 01 02 ff ff 83 c4 0c ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0 90 00 } //1
		$a_03_5 = {35 bf a0 be c7 45 90 01 01 8f 88 d6 9b 90 00 } //1
		$a_03_6 = {b3 74 18 e6 c7 45 90 01 01 35 bf a0 be 90 00 } //1
		$a_01_7 = {56 33 f6 80 3a 30 75 08 80 7a 01 78 75 02 42 42 8a 0a 8a c1 2c 30 3c 09 77 0c 0f be c1 c1 e6 04 8d 74 06 } //1
		$a_01_8 = {8d 41 0c c7 01 53 4d 53 54 89 51 08 c6 04 10 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=2
 
}