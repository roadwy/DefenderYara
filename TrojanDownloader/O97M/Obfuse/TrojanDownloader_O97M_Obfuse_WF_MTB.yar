
rule TrojanDownloader_O97M_Obfuse_WF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.WF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 47 53 41 20 3d 20 77 4b 67 4f 67 69 78 2e 43 72 65 61 74 65 28 4b 62 7a 6a 4c 43 75 63 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //01 00  MGSA = wKgOgix.Create(KbzjLCuc, Null, Null, intProcessID)
		$a_01_1 = {44 69 6d 20 77 4b 67 4f 67 69 78 2c 20 4b 62 7a 6a 4c 43 75 63 2c 20 4d 47 53 41 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 } //01 00  Dim wKgOgix, KbzjLCuc, MGSA, intProcessID
		$a_01_2 = {63 52 77 59 20 3d 20 52 61 6e 67 65 28 22 43 35 30 30 22 29 2e 43 6f 6d 6d 65 6e 74 2e 54 65 78 74 } //01 00  cRwY = Range("C500").Comment.Text
		$a_01_3 = {51 67 69 77 64 20 3d 20 53 70 6c 69 74 28 63 52 77 59 2c 20 22 2a 2a 2a 22 29 } //00 00  Qgiwd = Split(cRwY, "***")
	condition:
		any of ($a_*)
 
}