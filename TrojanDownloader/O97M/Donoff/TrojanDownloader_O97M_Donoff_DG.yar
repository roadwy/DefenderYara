
rule TrojanDownloader_O97M_Donoff_DG{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DG,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 50 50 44 41 74 61 22 } //01 00   = "PPDAta"
		$a_01_1 = {20 3d 20 22 65 61 64 2e 70 68 22 } //01 00   = "ead.ph"
		$a_01_2 = {20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 6f 63 75 6d 65 6e 74 73 2e 43 6f 75 6e 74 } //01 00   = Application.Documents.Count
		$a_01_3 = {20 3d 20 22 43 6d 64 2e 45 58 22 } //01 00   = "Cmd.EX"
		$a_01_4 = {20 3d 20 22 45 52 52 4f 22 } //01 00   = "ERRO"
		$a_01_5 = {20 3d 20 22 4f 41 64 46 69 6c 22 } //01 00   = "OAdFil"
		$a_01_6 = {20 3d 20 22 65 42 43 6c 69 65 22 } //01 00   = "eBClie"
		$a_01_7 = {20 3d 20 22 45 20 2f 43 20 22 22 22 } //01 00   = "E /C """
		$a_01_8 = {20 3d 20 22 74 74 70 3a 2f 2f 22 } //01 00   = "ttp://"
		$a_01_9 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 20 3d 20 } //00 00  ActiveDocument.Content.Text = 
		$a_00_10 = {5d 04 00 } //00 39 
	condition:
		any of ($a_*)
 
}