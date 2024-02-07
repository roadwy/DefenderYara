
rule TrojanDownloader_O97M_Ursnif_AMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 54 6f 6f 69 2c 20 41 62 73 28 43 49 6e 74 28 4e 61 64 73 29 29 20 2b 20 31 } //01 00  .SaveToFile Tooi, Abs(CInt(Nads)) + 1
		$a_01_1 = {63 65 6d 53 28 54 69 6f 28 22 74 73 2f 72 6e 73 74 6c 6f 68 70 2f 6f 69 65 6f 61 63 74 3a 6d 65 76 72 69 2e 6d 22 29 2c } //01 00  cemS(Tio("ts/rnstlohp/oieoact:mevri.m"),
		$a_01_2 = {54 69 6f 28 22 65 73 72 32 2f 20 72 67 76 33 20 73 22 29 20 26 20 72 } //01 00  Tio("esr2/ rgv3 s") & r
		$a_03_3 = {54 69 6f 28 22 69 6d 6d 73 77 6e 67 74 3a 22 29 3a 90 02 0f 3d 20 54 69 6f 28 22 69 32 72 65 57 33 50 63 73 6e 5f 6f 73 22 29 90 00 } //01 00 
		$a_03_4 = {28 22 22 20 26 20 90 02 0f 2c 20 4c 65 6e 28 90 1b 00 29 20 2a 20 38 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}