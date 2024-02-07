
rule TrojanDownloader_O97M_Powdow_BKSU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKSU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 73 66 73 64 20 3d 20 7a 78 63 7a 78 } //01 00  dasfsd = zxczx
		$a_01_1 = {43 61 6c 6c 20 62 68 65 6b 64 6c 73 76 2e 73 71 70 70 6d 6c 6d 78 78 72 78 65 6c 76 6d 73 67 6a 72 6a } //01 00  Call bhekdlsv.sqppmlmxxrxelvmsgjrj
		$a_01_2 = {64 73 66 64 73 61 20 3d 20 31 32 33 32 31 } //01 00  dsfdsa = 12321
		$a_01_3 = {65 77 70 62 6b 62 72 20 3d 20 37 30 20 2d 20 37 30 } //01 00  ewpbkbr = 70 - 70
		$a_03_4 = {2e 52 75 6e 28 90 02 32 2c 20 90 02 32 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}