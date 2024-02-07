
rule TrojanDownloader_Win32_Rugzip_A{
	meta:
		description = "TrojanDownloader:Win32/Rugzip.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 00 63 00 63 00 65 00 70 00 74 00 2d 00 4c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3a 00 20 00 72 00 75 00 } //01 00  Accept-Language: ru
		$a_00_1 = {41 00 63 00 63 00 65 00 70 00 74 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3a 00 20 00 67 00 7a 00 69 00 70 00 2c 00 20 00 64 00 65 00 66 00 6c 00 61 00 74 00 65 00 } //0a 00  Accept-Encoding: gzip, deflate
		$a_03_2 = {c8 00 00 00 8b f8 0f 85 90 01 02 00 00 3b fb 0f 84 90 01 02 00 00 8b 45 90 01 01 80 38 4d 0f 85 90 01 02 00 00 80 78 01 5a 0f 85 90 01 02 00 00 8d 45 90 01 01 6a 08 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}