
rule Adware_AndroidOS_MobiDash_B_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {70 10 bb d6 01 00 12 00 5b 10 90 01 02 12 00 5c 10 90 01 02 0e 00 06 00 02 00 04 00 03 00 90 01 02 4a 00 46 00 00 00 22 00 90 01 02 12 01 70 30 90 00 } //1
		$a_03_1 = {63 6f 6d 2f 6d 63 73 6b 69 6e 32 31 2f 44 72 65 61 6d 2f 90 02 20 6f 6e 43 72 65 61 74 65 90 00 } //1
		$a_01_2 = {63 6f 6d 2f 6d 63 73 6b 69 6e 32 31 2f 44 72 65 61 6d 2f 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //1 com/mcskin21/Dream/SplashActivity
		$a_01_3 = {73 65 74 41 64 4c 69 73 74 65 6e 65 72 } //1 setAdListener
		$a_01_4 = {6d 49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 mInterstitialAd
		$a_01_5 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_6 = {4d 6f 62 69 6c 65 41 64 73 2e 69 6e 69 74 69 61 6c 69 7a 65 } //1 MobileAds.initialize
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}