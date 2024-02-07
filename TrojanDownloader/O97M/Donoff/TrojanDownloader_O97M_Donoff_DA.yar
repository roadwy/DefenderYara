
rule TrojanDownloader_O97M_Donoff_DA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DA,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4b 58 56 53 75 4c 48 65 56 37 7a 28 29 20 41 73 20 53 74 72 69 6e 67 } //0a 00  Public Function KXVSuLHeV7z() As String
		$a_01_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4b 43 6c 6a 33 77 7a 42 69 45 4d 67 37 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Public Function KClj3wzBiEMg7() As String
		$a_03_2 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 09 09 00 2c 20 90 04 04 03 30 2d 39 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}