
rule Adware_AndroidOS_MobiDash_E_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6c 75 73 6b 61 63 72 65 77 6d 6f 64 73 2f 61 6d 6f 6e 67 6d 6f 64 73 } //01 00  com/luskacrewmods/amongmods
		$a_01_1 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //01 00  /system/app/Superuser.apk
		$a_01_2 = {4d 6f 62 69 6c 65 41 64 73 } //01 00  MobileAds
		$a_01_3 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //03 00  InterstitialAd
		$a_01_4 = {70 72 6f 70 75 62 6c 69 63 61 2e 64 62 } //03 00  propublica.db
		$a_01_5 = {73 70 69 63 65 37 2e 64 62 } //00 00  spice7.db
	condition:
		any of ($a_*)
 
}