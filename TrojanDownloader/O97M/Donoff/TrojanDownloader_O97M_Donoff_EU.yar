
rule TrojanDownloader_O97M_Donoff_EU{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EU,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2c 20 22 57 53 63 72 69 70 74 22 20 26 } //01 00  , "WScript" &
		$a_00_1 = {23 22 0d 0a 20 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e } //01 00 
		$a_02_2 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 16 29 2e 52 75 6e 28 4d 6f 64 75 6c 65 31 2e 90 02 16 28 90 02 16 2c 20 4c 54 72 69 6d 28 90 02 16 29 2c 20 22 22 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EU_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EU,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {4f 50 45 6e 28 29 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 90 12 40 00 28 22 90 02 10 3d 22 29 29 2e 56 61 6c 75 65 2c 20 76 62 48 69 64 65 29 3a 20 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 53 58 6d 6c 32 2e 64 6f 4d 64 6f 43 55 4d 45 4e 74 } //01 00  CreateObject("mSXml2.doMdoCUMENt
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 61 64 6f 64 42 2e 73 74 72 65 61 6d 22 29 } //00 00  CreateObject("adodB.stream")
	condition:
		any of ($a_*)
 
}