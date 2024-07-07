
rule TrojanDownloader_O97M_Obfuse_KC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 23 28 90 02 60 43 65 6c 6c 73 28 90 00 } //1
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 28 } //1 Application.International(
		$a_01_2 = {41 73 63 28 4d 69 64 24 28 } //1 Asc(Mid$(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_KC_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KC,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 53 68 65 6c 6c 28 73 74 72 50 72 6f 67 72 61 6d 4e 61 6d 65 2c 20 90 02 20 29 0d 0a 45 6e 64 20 53 75 62 90 00 } //10
		$a_03_1 = {20 3d 20 45 6e 76 69 72 6f 6e 90 02 01 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 53 70 6c 69 74 28 22 5c 41 70 70 44 61 74 61 5c 21 90 02 15 22 2c 20 22 21 22 29 28 30 29 20 2b 20 53 70 6c 69 74 28 22 90 02 15 21 22 20 26 20 70 61 74 68 5f 64 6f 6d 2c 20 22 21 22 29 28 31 29 20 2b 20 53 70 6c 69 74 28 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}