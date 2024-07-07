
rule TrojanDownloader_Win32_EyeStye_C{
	meta:
		description = "TrojanDownloader:Win32/EyeStye.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b c3 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 56 8b f0 8d 46 01 57 50 e8 88 04 00 00 33 ff 59 c6 04 30 00 85 f6 7e 0f 8d 4c 1e ff 8a 11 88 14 07 47 49 3b fe 7c f5 } //1
		$a_03_1 = {68 f4 01 00 00 ff d7 ff 90 01 02 8b 90 01 02 3b 05 90 01 04 76 90 01 01 c7 45 f4 90 01 04 c7 45 f8 90 01 04 c7 45 fc 90 01 04 33 ff 56 56 56 56 ff 90 01 03 56 6a 05 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 24 84 c0 74 90 00 } //1
		$a_03_2 = {33 f6 59 56 56 56 56 85 c0 75 90 01 01 68 90 01 04 eb 90 01 01 68 90 01 04 56 6a 05 68 90 01 04 68 90 01 04 e8 90 01 04 8b 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}