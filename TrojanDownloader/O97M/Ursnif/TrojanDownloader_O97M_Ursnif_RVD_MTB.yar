
rule TrojanDownloader_O97M_Ursnif_RVD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.RVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 70 70 52 29 2e 47 65 74 28 49 55 29 } //01 00  GetObject(ppR).Get(IU)
		$a_03_1 = {4d 4d 61 4b 2e 4f 70 65 6e 20 90 02 19 2c 20 56 69 55 2c 20 46 61 6c 73 65 2c 90 00 } //01 00 
		$a_01_2 = {6f 75 74 28 6e 50 4a 73 28 69 29 2c 20 6a 29 20 3d 20 4d 69 64 24 28 4d 69 6c 6c 57 2c 20 6b 2c 20 31 29 } //01 00  out(nPJs(i), j) = Mid$(MillW, k, 1)
		$a_01_3 = {47 67 75 69 64 61 28 22 61 45 58 32 4d 54 2e 30 31 4d 4d 2e 4c 54 36 4f 47 53 4c 58 48 50 2e 22 29 } //01 00  Gguida("aEX2MT.01MM.LT6OGSLXHP.")
		$a_01_4 = {54 72 61 64 75 63 65 28 47 67 75 69 64 61 28 22 51 68 70 2f 6f 6e 63 6f 5f 4a 74 73 2f 6d 61 2e 6d 3e 5c 74 3a 64 61 69 63 22 29 2c 20 6d 29 } //00 00  Traduce(Gguida("Qhp/onco_Jts/ma.m>\t:daic"), m)
	condition:
		any of ($a_*)
 
}