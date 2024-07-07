
rule PWS_Win32_Prefsap{
	meta:
		description = "PWS:Win32/Prefsap,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {6a 0d 6a 7c ff 75 dc ff 75 e0 e8 90 01 02 00 00 6a 0a 6a 5e ff 75 dc ff 75 e0 e8 90 01 02 00 00 ff 75 e8 ff 75 ec 6a ff ff 75 e0 ff 75 f0 68 90 01 02 00 10 ff 35 90 01 04 c3 83 f8 01 74 02 eb 90 00 } //2
		$a_01_1 = {8a 07 3c 41 72 08 3c 5a 77 04 04 20 eb 0a 3c 61 72 06 3c 7a 77 02 2c 20 88 07 47 49 0b c9 75 e0 } //1
		$a_03_2 = {24 3f 3c 3e 73 12 3c 34 73 0a 04 41 3c 5b 72 0f 04 06 eb 0b 04 fc eb 07 2c 3e c0 e0 02 04 2b 90 09 05 00 c1 c2 06 90 00 } //1
		$a_01_3 = {b1 07 8b c6 24 0f 3c 0a 1c 69 2f 88 04 11 c1 ee 04 49 79 ee } //1
		$a_01_4 = {89 45 f8 c7 00 53 53 49 44 68 } //2
		$a_01_5 = {72 6f 62 65 72 74 32 34 39 66 73 64 29 61 66 38 2e 3f 73 66 32 65 61 79 61 3b 73 64 24 25 38 35 30 33 34 67 73 6e 25 40 23 21 61 66 73 67 73 6a 64 67 3b 69 61 77 65 3b 6f 74 69 67 6b 62 61 72 72 } //1 robert249fsd)af8.?sf2eaya;sd$%85034gsn%@#!afsgsjdg;iawe;otigkbarr
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=4
 
}