
rule TrojanDownloader_Win32_Banload_APH{
	meta:
		description = "TrojanDownloader:Win32/Banload.APH,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {7d 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 0f b6 92 ?? ?? ?? 00 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb c7 } //1
		$a_03_1 = {7d 26 8b 45 fc 33 d2 6a 04 59 f7 f1 0f b6 82 ?? ?? ?? ?? 8b 4d 08 03 4d fc 0f b6 09 33 c8 8b 45 08 03 45 fc 88 08 eb cb } //1
		$a_01_2 = {68 53 11 70 6f 49 0e 70 70 54 00 } //10
		$a_01_3 = {09 08 48 75 6a 21 4c 11 3b 03 56 31 3b 04 4b 2a 31 09 00 00 09 08 48 75 6a 35 5a 35 3b 15 4b } //10
		$a_01_4 = {09 08 48 75 6a 35 5a 35 3b 15 4b 14 31 10 09 77 18 14 6d 26 3a 0e 4d 26 3d 13 56 2c 30 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=21
 
}