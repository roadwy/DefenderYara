
rule TrojanDownloader_O97M_AveMaria_BAK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AveMaria.BAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 75 73 61 20 3d 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 61 22 22 22 22 } //01 00  musa = """m" + "s" + "h" + "ta""""
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 25 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 32 30 25 32 30 40 62 69 74 2e 6c 79 2f 34 6b 6e 61 73 6b 6e 34 6b 61 6e 64 22 22 22 } //01 00  http://%20%20%20%2020%2020%2020%2020%20@bit.ly/4knaskn4kand"""
		$a_01_2 = {3d 20 53 70 6c 69 74 28 52 65 70 6c 61 63 65 28 70 54 61 67 73 2c 20 22 20 22 2c 20 22 22 29 2c 20 22 2c 22 29 } //00 00  = Split(Replace(pTags, " ", ""), ",")
	condition:
		any of ($a_*)
 
}