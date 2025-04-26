
rule Adware_AndroidOS_MobiDash_U_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 72 64 76 69 65 77 2e 64 62 } //1 cardview.db
		$a_01_1 = {4d 6f 62 69 6c 65 41 64 73 } //1 MobileAds
		$a_01_2 = {69 64 65 2f 63 72 65 61 74 6f 72 2f 6e 67 61 62 65 61 6e 2f 63 61 72 64 76 69 65 77 } //1 ide/creator/ngabean/cardview
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_4 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Adware_AndroidOS_MobiDash_U_MTB_2{
	meta:
		description = "Adware:AndroidOS/MobiDash.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 61 6c 6b 69 6e 67 2f 6e 6f 65 6c 2f 50 72 6f 76 69 64 65 72 } //1 com/talking/noel/Provider
		$a_01_1 = {6e 6f 65 6c 2e 64 62 } //1 noel.db
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
		$a_01_4 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}