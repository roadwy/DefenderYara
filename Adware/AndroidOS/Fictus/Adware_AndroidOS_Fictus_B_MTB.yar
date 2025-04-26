
rule Adware_AndroidOS_Fictus_B_MTB{
	meta:
		description = "Adware:AndroidOS/Fictus.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 72 69 78 61 6c 6c 61 62 2f 61 64 73 2f 61 64 73 } //1 com/rixallab/ads/ads
		$a_01_1 = {61 64 73 30 31 2e 61 64 65 63 6f 73 79 73 74 65 6d 73 2e 63 6f 6d } //1 ads01.adecosystems.com
		$a_01_2 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_3 = {70 72 65 6c 6f 61 64 41 64 } //1 preloadAd
		$a_01_4 = {63 6f 6d 2f 76 64 6f 70 69 61 2f 61 6e 64 72 6f 69 64 2f 70 72 65 72 6f 6c 6c } //1 com/vdopia/android/preroll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}