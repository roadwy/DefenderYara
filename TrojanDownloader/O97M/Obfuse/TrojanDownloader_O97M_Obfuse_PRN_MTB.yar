
rule TrojanDownloader_O97M_Obfuse_PRN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6c 31 6c 31 6c 28 22 } //01 00  = CreateObject(l1l1l("
		$a_02_1 = {3d 20 52 65 70 6c 61 63 65 28 6c 31 31 6c 31 31 2c 20 6c 31 6c 31 6c 28 22 90 02 0f 22 2c 20 22 27 58 22 29 2c 20 22 22 29 90 00 } //01 00 
		$a_00_2 = {6c 31 6c 6c 31 6c 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c } //01 00  l1ll1l = URLDownloadToFile(0,
		$a_00_3 = {6c 31 31 6c 6c 6c 2e 52 75 6e 20 43 68 72 28 33 34 29 20 26 20 6c 31 31 6c 6c 31 20 } //01 00  l11lll.Run Chr(34) & l11ll1 
		$a_00_4 = {3d 20 41 72 72 61 79 28 6c 31 6c 31 6c 28 22 } //00 00  = Array(l1l1l("
	condition:
		any of ($a_*)
 
}