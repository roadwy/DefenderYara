
rule TrojanDownloader_O97M_Bartallex_Y{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.Y,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 6f 72 65 6e 65 62 65 64 61 5f 34 20 3d 20 67 6f 72 65 6e 65 62 65 64 61 5f 33 28 6f 6e 6f 70 72 69 64 65 74 28 36 29 29 } //01 00  gorenebeda_4 = gorenebeda_3(onopridet(6))
		$a_00_1 = {67 6f 72 65 6e 65 62 65 64 61 5f 35 20 3d 20 67 6f 72 65 6e 65 62 65 64 61 5f 34 20 2b 20 52 65 70 6c 61 63 65 28 6f 6e 6f 70 72 69 64 65 74 28 31 32 29 2c 20 22 74 22 2c 20 22 65 22 29 } //01 00  gorenebeda_5 = gorenebeda_4 + Replace(onopridet(12), "t", "e")
		$a_00_2 = {6f 6e 6f 70 72 69 64 65 74 20 3d 20 53 70 6c 69 74 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 2c 20 22 2f 22 29 } //01 00  onopridet = Split(UserForm1.Label1.Caption, "/")
		$a_00_3 = {53 65 74 20 67 6f 72 65 6e 65 62 65 64 61 5f 36 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6f 6e 6f 70 72 69 64 65 74 28 32 29 29 } //01 00  Set gorenebeda_6 = CreateObject(onopridet(2))
		$a_00_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 6f 6e 6f 70 72 69 64 65 74 28 33 29 29 } //01 00  CreateObject(onopridet(3))
		$a_00_5 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 6f 6e 6f 70 72 69 64 65 74 28 34 29 29 } //00 00  .Environment(onopridet(4))
	condition:
		any of ($a_*)
 
}