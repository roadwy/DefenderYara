
rule Adware_AndroidOS_Hiddad_C_MTB{
	meta:
		description = "Adware:AndroidOS/Hiddad.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 41 64 4c 6f 61 64 4c 69 73 74 65 6e 65 72 } //01 00  setAdLoadListener
		$a_01_1 = {6f 6e 41 64 43 6c 69 63 6b 65 64 } //01 00  onAdClicked
		$a_01_2 = {4c 6f 61 64 41 70 70 6c 6f 76 69 6e 46 75 6c 6c 41 64 73 } //01 00  LoadApplovinFullAds
		$a_01_3 = {61 64 48 69 64 64 65 6e } //01 00  adHidden
		$a_01_4 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //01 00  InterstitialAd
		$a_01_5 = {4c 6f 61 64 42 61 6e 6e 65 72 46 62 76 69 65 77 } //01 00  LoadBannerFbview
		$a_01_6 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //00 00  setComponentEnabledSetting
	condition:
		any of ($a_*)
 
}