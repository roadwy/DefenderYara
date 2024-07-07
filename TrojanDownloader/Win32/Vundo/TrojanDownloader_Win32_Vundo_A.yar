
rule TrojanDownloader_Win32_Vundo_A{
	meta:
		description = "TrojanDownloader:Win32/Vundo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00 } //1
		$a_02_1 = {8b 48 28 85 c9 74 14 a1 90 01 03 10 6a 00 03 c8 6a 03 50 89 0d 90 01 03 10 ff d1 c3 90 00 } //1
		$a_02_2 = {8a 00 88 45 b0 0f b6 45 ac 0f b6 4d b0 33 c1 8b 0d 90 01 03 10 03 0d 90 01 03 10 88 01 e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Vundo_A_2{
	meta:
		description = "TrojanDownloader:Win32/Vundo.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 39 64 69 65 69 33 39 2d 64 38 33 6b 64 6a 65 69 2d 64 6b 63 38 65 64 69 2d 64 6b 64 69 65 6b 66 75 } //1 39diei39-d83kdjei-dkc8edi-dkdiekfu
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {49 00 50 00 76 00 36 00 20 00 49 00 2d 00 41 00 6d 00 2d 00 48 00 65 00 72 00 65 00 } //1 IPv6 I-Am-Here
		$a_01_3 = {49 00 50 00 76 00 36 00 20 00 57 00 68 00 65 00 72 00 65 00 2d 00 41 00 72 00 65 00 2d 00 59 00 6f 00 75 00 } //1 IPv6 Where-Are-You
		$a_03_4 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 90 01 04 50 8b 45 fc e8 90 01 04 50 6a 00 e8 90 01 04 85 c0 75 04 b3 01 eb 02 33 db 33 c0 90 00 } //1
		$a_03_5 = {8b 45 f8 89 45 f0 8b 45 e4 8b 40 08 89 45 e0 81 45 e0 48 02 00 00 6a 04 8d 4d f0 8b 55 e0 8b c7 e8 90 01 04 8b 45 f0 c1 e8 04 c1 e0 04 03 45 f8 89 45 f0 6a 04 8d 4d f0 8b 55 e0 8b c7 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}