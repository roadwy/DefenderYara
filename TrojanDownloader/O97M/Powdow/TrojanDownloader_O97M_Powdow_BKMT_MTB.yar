
rule TrojanDownloader_O97M_Powdow_BKMT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 74 77 67 20 3d 20 6f 74 77 67 20 26 20 } //01 00  otwg = otwg & 
		$a_01_1 = {2e 52 75 6e 28 77 6a 74 74 61 77 75 6f 6f 61 78 6a 6b 63 6b 2c 20 64 6b 6e 74 6c 67 6b 74 70 73 64 6b 74 66 75 29 } //01 00  .Run(wjttawuooaxjkck, dkntlgktpsdktfu)
		$a_01_2 = {3d 20 43 68 72 28 66 73 63 76 20 2d 20 31 32 31 29 } //00 00  = Chr(fscv - 121)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_BKMT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 64 34 35 63 76 76 30 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00  .ShellExecute "P" + fd45cvv0, fgfjhfgfg, "", "", 0
		$a_01_1 = {3d 20 47 78 68 74 4b 45 6d 28 42 61 56 75 2c 20 6c 4c 53 55 29 } //01 00  = GxhtKEm(BaVu, lLSU)
		$a_01_2 = {42 4b 4a 61 48 66 45 2e 4e 61 6d 65 20 3d 20 22 43 6f 6d 6d 65 6e 74 73 22 20 54 68 65 6e } //00 00  BKJaHfE.Name = "Comments" Then
	condition:
		any of ($a_*)
 
}