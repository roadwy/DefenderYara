
rule TrojanDownloader_O97M_Donoff_EH{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EH,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 66 20 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 45 6d 62 65 64 4c 69 6e 67 75 69 73 74 69 63 44 61 74 61 29 20 54 68 65 6e } //0a 00  If (ActiveDocument.EmbedLinguisticData) Then
		$a_03_1 = {4e 65 78 74 20 90 02 10 0d 0a 90 02 10 20 3d 20 53 68 65 6c 6c 28 90 02 0a 2c 20 90 02 0a 29 90 00 } //01 00 
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 90 02 10 28 29 0d 0a 90 02 10 20 3d 20 45 6d 70 74 79 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_3 = {46 75 6e 63 74 69 6f 6e 20 90 02 10 28 29 0d 0a 90 02 10 20 3d 20 45 6d 70 74 79 0d 0a 90 02 10 20 3d 20 90 02 10 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_4 = {46 75 6e 63 74 69 6f 6e 20 90 02 10 28 29 0d 0a 90 02 10 20 3d 20 46 61 6c 73 65 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_5 = {46 75 6e 63 74 69 6f 6e 20 90 02 10 28 29 0d 0a 90 02 10 20 3d 20 46 61 6c 73 65 0d 0a 90 02 10 20 3d 20 90 02 10 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_6 = {46 75 6e 63 74 69 6f 6e 20 90 02 10 28 29 0d 0a 90 02 10 20 3d 20 54 72 75 65 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 48 9b 03 80 5c 2c 00 } //00 49 
	condition:
		any of ($a_*)
 
}