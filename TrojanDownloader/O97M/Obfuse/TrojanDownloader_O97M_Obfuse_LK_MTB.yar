
rule TrojanDownloader_O97M_Obfuse_LK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 90 02 10 28 29 20 26 20 22 5c 90 02 10 2e 78 22 20 26 20 90 02 14 28 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_01_1 = {3d 20 22 61 70 70 64 61 74 61 22 } //01 00  = "appdata"
		$a_01_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //01 00  = New WshShell
		$a_01_3 = {22 73 6c 22 } //01 00  "sl"
		$a_01_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 28 } //01 00  Debug.Print Error(
		$a_01_5 = {2e 54 65 78 74 20 26 } //00 00  .Text &
	condition:
		any of ($a_*)
 
}