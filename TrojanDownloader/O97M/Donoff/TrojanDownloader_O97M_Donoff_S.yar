
rule TrojanDownloader_O97M_Donoff_S{
	meta:
		description = "TrojanDownloader:O97M/Donoff.S,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 68 74 24 74 70 24 3a 2f } //01 00  "ht$tp$:/
		$a_01_1 = {22 68 3f 3f 74 74 3f 3f 70 3a 2f } //01 00  "h??tt??p:/
		$a_02_2 = {45 6e 76 69 72 6f 6e 28 52 65 70 6c 61 63 65 28 22 90 02 07 74 90 02 07 6d 90 02 07 70 90 00 } //01 00 
		$a_00_3 = {2c 20 22 24 22 2c 20 22 22 29 29 } //01 00  , "$", ""))
		$a_02_4 = {52 65 70 6c 61 63 65 28 22 4f 90 02 07 70 90 02 07 65 90 02 07 6e 90 00 } //01 00 
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c } //00 00  ShellExecuteW 0&,
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}