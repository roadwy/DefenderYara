
rule TrojanDownloader_O97M_Skebpac_B{
	meta:
		description = "TrojanDownloader:O97M/Skebpac.B,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 74 61 74 75 73 20 3d 20 90 02 08 28 45 76 61 6c 75 61 74 65 28 90 02 03 20 2d 20 90 02 03 29 22 29 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 22 20 26 } //01 00  http:" &
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 20 45 76 61 6c 75 61 74 65 28 } //01 00  ShellExecuteA Evaluate(
		$a_00_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c } //01 00  = Environ("TEMP") & "\
		$a_00_4 = {26 20 22 75 70 64 2e 65 78 22 20 26 } //01 00  & "upd.ex" &
		$a_00_5 = {26 20 22 2f 6f 66 66 69 63 65 2e 65 78 22 20 26 } //00 00  & "/office.ex" &
	condition:
		any of ($a_*)
 
}