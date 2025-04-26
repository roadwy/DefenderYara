
rule Adware_AndroidOS_MobiDash_O_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 37 39 34 37 33 34 2e 64 62 } //1 app794734.db
		$a_01_1 = {63 6f 6d 2f 61 6c 6c 61 68 77 61 6c 6c 70 61 70 65 72 2f 68 64 77 61 6c 6c 70 61 70 65 72 2f 61 6c 6c 61 68 2f 69 73 6c 61 6d 69 63 2f 6b 61 6c 69 67 72 61 66 69 2f 61 70 70 37 39 34 37 33 34 } //1 com/allahwallpaper/hdwallpaper/allah/islamic/kaligrafi/app794734
		$a_01_2 = {4d 6f 62 69 6c 65 41 64 73 } //1 MobileAds
		$a_01_3 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_4 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}