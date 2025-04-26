
rule TrojanDownloader_Win32_Cutwail_AP{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {80 38 4d 75 1f 80 78 01 5a 75 19 } //2
		$a_01_1 = {6a 19 33 d2 59 f7 f1 80 c2 61 eb 13 3c 58 } //2
		$a_01_2 = {66 83 7e 06 00 8d 7c 30 18 76 31 83 c7 14 } //1
		$a_01_3 = {80 78 50 69 } //1
		$a_01_4 = {80 78 51 7a 0f 94 c1 8b c1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Cutwail_AP_2{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1b 81 f3 ?? ?? ?? ?? 81 fb } //2
		$a_01_1 = {25 00 00 ff ff 05 00 30 00 00 } //1
		$a_01_2 = {8b c0 ff 73 50 } //1
		$a_01_3 = {6a 00 e2 fc } //1
		$a_01_4 = {31 03 83 c3 04 } //1
		$a_01_5 = {66 b8 01 10 57 5f 66 48 66 81 3a 4d 5a } //2
		$a_01_6 = {be 93 a2 88 91 97 8c af 81 9d } //2
		$a_01_7 = {f2 df ee c1 c4 dc cd da fc c7 c3 cd c6 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=3
 
}