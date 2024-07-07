
rule Adware_AndroidOS_MobiDash_K_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 6e 69 64 6f 73 70 61 72 61 64 6f 72 6d 69 72 2e 64 62 } //1 sonidosparadormir.db
		$a_01_1 = {6d 6f 62 69 6c 65 61 64 73 } //1 mobileads
		$a_01_2 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}