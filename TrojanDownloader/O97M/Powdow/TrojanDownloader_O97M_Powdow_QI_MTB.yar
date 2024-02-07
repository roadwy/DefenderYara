
rule TrojanDownloader_O97M_Powdow_QI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.QI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 61 73 6b 64 6b 2e 68 69 73 73 73 73 61 } //01 00  kaskdk.hissssa
		$a_00_1 = {53 75 62 20 68 69 73 73 73 73 61 28 29 } //01 00  Sub hissssa()
		$a_00_2 = {53 68 65 6c 6c 20 70 6b 6b 6b 6b } //01 00  Shell pkkkk
		$a_00_3 = {74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f } //01 00  tp://%748237%728748@j.mp/
		$a_00_4 = {61 64 67 6b 73 68 6b 61 73 67 64 68 61 67 73 64 6a 61 62 6e 76 63 6e 7a 78 } //01 00  adgkshkasgdhagsdjabnvcnzx
		$a_00_5 = {70 64 61 73 33 20 3d 20 22 74 22 20 2b 20 22 61 20 68 74 22 } //00 00  pdas3 = "t" + "a ht"
	condition:
		any of ($a_*)
 
}