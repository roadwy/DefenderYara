
rule TrojanDownloader_O97M_Ursnif_BA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 90 02 30 5c 90 02 20 2e 78 73 22 20 2b 20 90 02 20 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 90 02 10 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 22 90 0c 02 00 50 75 62 6c 69 63 20 43 6f 6e 73 74 20 90 02 10 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5c 74 22 90 00 } //01 00 
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 } //01 00  Debug.Print Error
		$a_01_3 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 } //01 00  Call VBA.Shell@(StrReverse
		$a_01_4 = {3d 20 22 22 } //01 00  = ""
		$a_01_5 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //00 00  = New WshShell
	condition:
		any of ($a_*)
 
}