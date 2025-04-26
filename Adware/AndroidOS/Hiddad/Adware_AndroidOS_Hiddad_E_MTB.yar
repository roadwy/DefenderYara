
rule Adware_AndroidOS_Hiddad_E_MTB{
	meta:
		description = "Adware:AndroidOS/Hiddad.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 72 65 67 69 73 74 65 72 5f 61 64 73 2e 70 68 70 } //2 /register_ads.php
		$a_01_1 = {6f 6e 41 64 4c 6f 61 64 65 64 } //1 onAdLoaded
		$a_01_2 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 4c 69 73 74 65 6e 65 72 } //1 InterstitialAdListener
		$a_01_3 = {6f 6e 41 64 43 6c 69 63 6b 65 64 } //1 onAdClicked
		$a_01_4 = {72 65 67 69 73 74 65 72 41 64 73 28 29 2e 65 78 65 63 75 74 65 28 29 } //1 registerAds().execute()
		$a_01_5 = {6f 6e 4d 65 64 69 61 44 6f 77 6e 6c 6f 61 64 65 64 } //1 onMediaDownloaded
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}