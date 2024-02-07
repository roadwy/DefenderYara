
rule TrojanDownloader_MacOS_SAgnt_B_MTB{
	meta:
		description = "TrojanDownloader:MacOS/SAgnt.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 cc 48 89 55 98 48 89 4d 90 01 01 e8 90 01 02 ff ff 41 b8 90 01 01 00 00 00 44 89 c6 48 89 05 90 01 02 00 00 48 89 15 90 01 02 00 00 48 8d 3d 90 01 02 00 00 ba 01 00 00 00 e8 90 01 02 00 00 41 b8 0c 00 00 00 44 89 c6 48 8d 3d 90 01 02 00 00 41 b8 01 00 00 00 48 89 55 88 44 89 c2 48 89 45 80 e8 90 01 02 00 00 48 89 45 d8 48 89 55 e0 48 8d 45 e8 90 00 } //01 00 
		$a_01_1 = {3d 75 3f 6e 61 69 64 72 61 75 67 2f } //01 00  =u?naidraug/
		$a_01_2 = {68 73 61 62 2f 6e 69 62 2f } //00 00  hsab/nib/
	condition:
		any of ($a_*)
 
}