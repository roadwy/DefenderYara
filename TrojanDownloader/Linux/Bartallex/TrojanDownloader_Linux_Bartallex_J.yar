
rule TrojanDownloader_Linux_Bartallex_J{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.J,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 20 43 68 72 28 36 30 29 2c 20 22 22 29 0d 0a 90 05 18 06 41 2d 5a 61 2d 7a 20 3d 20 52 65 70 6c 61 63 65 28 90 1b 00 2c 20 43 68 72 28 36 31 29 2c 20 22 22 29 0d 0a 90 1b 00 20 3d 20 52 65 70 6c 61 63 65 28 90 1b 00 2c 20 43 68 72 28 35 39 29 2c 20 22 22 29 90 08 ff 03 70 61 74 68 49 73 41 62 73 6f 6c 75 74 65 5f 31 20 3d 20 68 43 75 72 44 69 72 5f 32 28 43 68 72 28 38 37 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}