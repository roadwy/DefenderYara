
rule Adware_AndroidOS_MobiDash_H_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 6d 66 6c 61 62 73 2f 73 77 69 6d 6d 69 6e 67 74 75 74 6f 72 69 61 6c 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //02 00  com/tmflabs/swimmingtutorial/MainActivity
		$a_01_1 = {6f 6d 2f 6f 73 73 69 62 75 73 73 6f 66 74 77 61 72 65 2f 64 65 61 64 70 69 78 65 6c 74 65 73 74 2f 50 72 6f 76 69 64 65 72 } //01 00  om/ossibussoftware/deadpixeltest/Provider
		$a_01_2 = {4d 6f 62 69 6c 65 41 64 73 } //01 00  MobileAds
		$a_01_3 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //01 00  InterstitialAd
		$a_01_4 = {64 65 61 64 70 69 78 65 6c 74 65 73 74 2e 64 62 } //01 00  deadpixeltest.db
		$a_01_5 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00  DexClassLoader
	condition:
		any of ($a_*)
 
}