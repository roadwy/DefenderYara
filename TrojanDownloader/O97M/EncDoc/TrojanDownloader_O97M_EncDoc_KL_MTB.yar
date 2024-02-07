
rule TrojanDownloader_O97M_EncDoc_KL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 20 3d 20 22 68 74 74 70 3a 2f 2f 74 6f 70 76 61 6c 75 61 74 69 6f 6e 66 69 72 6d 73 2e 63 6f 6d 2f 6b 6b 72 61 6b 65 6e 2e 70 6e 67 22 } //01 00  U = "http://topvaluationfirms.com/kkraken.png"
		$a_01_1 = {4e 20 3d 20 22 6b 6b 72 61 6b 65 6e 2e 70 6e 67 22 } //01 00  N = "kkraken.png"
		$a_01_2 = {41 73 79 6e 63 20 3d 20 22 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 22 } //01 00  Async = "DownloadFileAsync"
		$a_01_3 = {67 46 78 31 37 4c 4f 61 2e 4f 70 65 6e 20 45 57 41 2c 20 55 2c 20 46 61 6c 73 65 } //00 00  gFx17LOa.Open EWA, U, False
	condition:
		any of ($a_*)
 
}