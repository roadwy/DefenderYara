
rule TrojanDownloader_O97M_Donoff_DP{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DP,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //01 00  = CreateObject(
		$a_00_1 = {3d 20 54 79 70 65 4e 61 6d 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 64 65 4e 61 6d 65 29 20 3d 20 22 53 74 72 69 6e 67 } //01 00  = TypeName(ActiveDocument.CodeName) = "String
		$a_02_2 = {54 68 65 6e 0d 0a 90 02 0f 20 3d 20 41 72 72 61 79 28 90 00 } //01 00 
		$a_02_3 = {3d 20 41 72 72 61 79 28 4a 6f 69 6e 28 90 02 0f 2c 20 90 02 0f 29 29 28 30 29 90 00 } //01 00 
		$a_02_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 90 02 0f 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}