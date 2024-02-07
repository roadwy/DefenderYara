
rule TrojanDownloader_O97M_Obfuse_RVBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 41 4d 45 4d 45 2e 4a 50 56 75 7a 28 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6c 45 53 48 28 29 2c 20 77 50 44 4c 6f 28 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 30 29 } //01 00  NAMEME.JPVuz().ShellExecute(lESH(), wPDLo(), Null, Null, 0)
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 47 63 64 7a 75 48 28 29 29 } //01 00  = GetObject(GcdzuH())
		$a_01_2 = {2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } //01 00  .Shapes(1).TextFrame.Characters.Text
		$a_01_3 = {77 50 44 4c 6f 20 3d 20 28 22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 49 73 74 7a 35 29 } //01 00  wPDLo = ("ping google.com;" + Istz5)
		$a_01_4 = {28 22 70 22 20 2b 20 49 73 74 7a 36 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}