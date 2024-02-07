
rule TrojanDownloader_O97M_EncDoc_STUV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STUV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 74 20 6c 65 65 6b 20 3d 20 22 7a 70 6f 67 61 64 6f 6d 65 6e 74 22 } //01 00  Const leek = "zpogadoment"
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 70 72 65 6e 64 2e 62 } //01 00  C:\Users\Public\aprend.b
		$a_01_2 = {52 65 70 6c 61 63 65 28 22 70 6f 77 4b 66 6d 6d 64 36 37 72 73 68 4b 66 6d 6d 64 36 37 6c 6c 22 2c 20 22 4b 66 6d 6d 64 36 37 22 2c 20 22 5e 65 5e 22 29 } //01 00  Replace("powKfmmd67rshKfmmd67ll", "Kfmmd67", "^e^")
		$a_03_3 = {26 20 22 20 2d 77 20 68 69 64 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 33 3b 53 74 61 5e 72 74 2d 42 5e 69 74 73 54 5e 72 61 5e 6e 73 66 65 5e 72 20 2d 53 6f 75 20 68 74 74 5e 70 3a 2f 2f 64 64 6c 37 2e 64 61 74 61 2e 68 75 2f 67 65 74 2f 90 02 1f 2f 90 02 1f 2f 90 02 1f 2e 65 78 5e 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 02 1f 2e 65 5e 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 02 1f 2e 65 5e 78 65 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}