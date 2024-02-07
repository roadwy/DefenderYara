
rule TrojanDownloader_O97M_Donoff_CM{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CM,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 76 65 41 6c 6c 53 74 75 66 41 6e 64 45 78 69 74 28 53 6f 75 72 63 65 46 69 6c 65 20 41 73 20 53 74 72 69 6e 67 2c 20 44 65 73 74 46 69 6c 65 20 41 73 20 53 74 72 69 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 4b 65 79 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  SaveAllStufAndExit(SourceFile As String, DestFile As String, Optional Key As String)
		$a_03_1 = {69 66 63 6f 6e 66 69 67 90 02 14 20 3d 20 53 70 6c 69 74 28 90 00 } //01 00 
		$a_03_2 = {69 66 63 6f 6e 66 69 67 90 02 14 2e 4f 70 65 6e 20 90 00 } //01 00 
		$a_03_3 = {69 66 63 6f 6e 66 69 67 90 02 14 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 69 66 63 6f 6e 66 69 67 90 02 14 2c 20 22 4d 6f 7a 69 6c 6c 61 2f 90 00 } //01 00 
		$a_03_4 = {53 61 76 65 41 6c 6c 53 74 75 66 41 6e 64 45 78 69 74 20 69 66 63 6f 6e 66 69 67 90 02 14 2c 20 69 66 63 6f 6e 66 69 67 90 02 14 2c 20 22 90 00 } //00 00 
		$a_00_5 = {96 dd } //00 00 
	condition:
		any of ($a_*)
 
}