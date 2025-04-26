
rule Adware_AndroidOS_Mobidash_W_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 00 00 10 23 01 ?? ?? 12 02 6e 40 ?? ?? 15 02 0a 03 3d 03 06 00 6e 40 ?? ?? 16 32 28 f6 0e 00 } //1
		$a_01_1 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_2 = {4d 6f 62 69 6c 65 41 64 73 } //1 MobileAds
		$a_01_3 = {70 69 6e 66 6f } //1 pinfo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}