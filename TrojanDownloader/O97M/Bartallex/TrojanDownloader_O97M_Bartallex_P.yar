
rule TrojanDownloader_O97M_Bartallex_P{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.P,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 05 28 43 68 72 28 90 02 03 29 20 2b 90 00 } //01 00 
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 05 28 43 68 72 28 90 02 03 29 20 2b 90 00 } //01 00 
		$a_03_2 = {2e 4f 70 65 6e 20 90 02 05 28 43 68 72 28 90 02 03 29 20 2b 90 00 } //01 00 
		$a_01_3 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e } //01 00  .Status = 200 Then
		$a_01_4 = {2e 63 52 65 61 74 65 74 65 58 74 66 49 6c 65 28 } //01 00  .cReateteXtfIle(
		$a_01_5 = {29 29 2e 52 75 6e 20 22 22 22 22 20 26 } //00 00  )).Run """" &
	condition:
		any of ($a_*)
 
}