
rule TrojanDownloader_Win32_Banload_AMA{
	meta:
		description = "TrojanDownloader:Win32/Banload.AMA,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {89 75 98 89 5d 90 89 8d 68 ff ff ff c7 85 60 ff ff ff 08 40 00 00 ff d7 } //1
		$a_03_1 = {b9 ff 00 00 00 66 3b c1 7e 05 0f bf c0 eb ?? 8b 55 } //1
		$a_01_2 = {b8 1e 00 00 00 0f bf c0 03 c1 0f 80 35 01 00 00 2b c6 0f 80 2d 01 00 00 50 8d 45 90 50 ff 15 } //1
		$a_01_3 = {0f bf ca 33 c0 0f bf c0 03 c1 0f 80 35 01 00 00 2b c6 0f 80 2d 01 00 00 50 8d 45 90 50 ff 15 } //1
		$a_01_4 = {5c 00 62 00 69 00 6e 00 5c 00 70 00 72 00 6f 00 6a 00 65 00 74 00 6f 00 2e 00 76 00 62 00 70 00 00 00 } //5
		$a_01_5 = {52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 00 00 } //1
		$a_01_6 = {52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 00 00 } //1
		$a_01_7 = {77 00 69 00 6e 00 64 00 69 00 72 00 00 00 } //1
		$a_01_8 = {52 00 65 00 67 00 52 00 65 00 61 00 64 00 00 00 } //1
		$a_01_9 = {52 00 45 00 47 00 5f 00 53 00 5a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=13
 
}