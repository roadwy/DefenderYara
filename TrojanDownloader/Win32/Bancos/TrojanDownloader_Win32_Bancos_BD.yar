
rule TrojanDownloader_Win32_Bancos_BD{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 45 f6 d3 e8 f6 d0 30 45 eb 8d 55 eb b9 01 00 00 00 8b 45 ec 8b 38 ff 57 14 46 4b 75 cf } //1
		$a_01_1 = {7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 } //1
		$a_03_2 = {c7 45 b8 44 00 00 00 c7 45 e4 01 00 00 00 66 c7 45 e8 00 00 8d 45 a8 50 8d 45 b8 50 6a 00 6a 00 68 90 90 00 00 00 6a 00 6a 00 6a 00 8b 45 fc e8 90 01 04 50 6a 00 e8 90 01 04 83 f8 01 90 00 } //1
		$a_03_3 = {0f b6 44 30 ff 33 d8 8d 45 d0 50 89 5d d4 c6 45 d8 00 8d 55 d4 33 c9 b8 90 01 04 e8 90 01 04 8b 55 d0 8d 45 ec e8 90 01 04 8b fb ff 45 e8 ff 4d e0 75 a3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}