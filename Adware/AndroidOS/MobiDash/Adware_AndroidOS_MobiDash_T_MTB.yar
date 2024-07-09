
rule Adware_AndroidOS_MobiDash_T_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {04 00 0c 01 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 04 00 0c 04 6e 10 ?? ?? 02 00 6e 20 ?? ?? 04 00 0c 04 22 00 ?? ?? ?? ?? ?? ?? 10 00 70 30 ?? ?? 43 00 28 05 0d 04 } //1
		$a_01_1 = {61 6e 63 69 65 6e 74 72 6f 6d 65 2e 64 62 } //1 ancientrome.db
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
		$a_01_4 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_5 = {4d 6f 62 69 6c 65 41 64 73 } //1 MobileAds
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}