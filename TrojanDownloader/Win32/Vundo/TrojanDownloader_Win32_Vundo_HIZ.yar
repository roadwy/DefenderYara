
rule TrojanDownloader_Win32_Vundo_HIZ{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HIZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 40 10 8b 04 85 e8 3e 41 00 8a 00 88 45 c0 a1 d0 3e 41 00 03 05 4c 36 41 00 8a 00 32 45 c0 8b 0d d0 3e 41 00 03 0d 4c 36 41 00 88 01 e9 99 fe ff ff } //1
		$a_01_1 = {e8 37 35 00 00 e8 fb 5c ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Vundo_HIZ_2{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HIZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 10 8b 48 28 85 c9 74 14 a1 90 01 02 00 10 6a 00 03 c8 6a 90 01 01 50 89 0d 90 01 02 00 10 ff d1 c3 90 00 } //1
		$a_03_1 = {31 48 04 a1 90 01 04 8b 0d 90 01 04 31 48 08 90 00 } //1
		$a_00_2 = {03 03 ff e0 83 7c 24 08 01 } //1
		$a_01_3 = {0f b7 55 f4 33 4d f4 33 c2 5f 5e 66 85 c9 75 05 b8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}