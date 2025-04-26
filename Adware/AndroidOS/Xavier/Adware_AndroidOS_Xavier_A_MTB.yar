
rule Adware_AndroidOS_Xavier_A_MTB{
	meta:
		description = "Adware:AndroidOS/Xavier.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {58 61 76 69 65 72 43 6f 6e 66 69 67 48 75 62 } //1 XavierConfigHub
		$a_01_1 = {6f 6e 49 6e 74 65 72 73 74 69 74 69 61 6c 44 69 73 6d 69 73 73 65 64 } //1 onInterstitialDismissed
		$a_01_2 = {63 61 6e 53 68 6f 77 53 74 61 72 74 41 70 70 49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 4f 6e 4c 61 75 6e 63 68 } //1 canShowStartAppInterstitialAdOnLaunch
		$a_01_3 = {73 68 6f 77 41 64 4d 6f 62 49 6e 74 65 72 73 74 69 74 69 61 6c } //1 showAdMobInterstitial
		$a_01_4 = {63 61 6e 53 68 6f 77 46 42 49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 4f 6e 4c 61 75 6e 63 68 } //1 canShowFBInterstitialAdOnLaunch
		$a_01_5 = {73 61 76 65 53 74 61 72 74 41 70 70 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 saveStartAppConfiguration
		$a_01_6 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}