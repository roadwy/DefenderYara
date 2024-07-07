
rule Adware_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "Adware:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 75 2f 6d 61 69 6c 2f 75 73 61 2f 61 6e 64 72 6f 69 64 2f 6d 79 74 61 72 67 65 74 2f 61 64 73 } //1 ru/mail/usa/android/mytarget/ads
		$a_01_1 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //1 /system/app/Superuser.apk
		$a_01_3 = {4d 6f 62 69 6c 65 41 64 73 } //1 MobileAds
		$a_01_4 = {4f 6e 41 70 70 49 6e 73 74 61 6c 6c 41 64 4c 6f 61 64 65 64 4c 69 73 74 65 6e 65 72 } //1 OnAppInstallAdLoadedListener
		$a_01_5 = {67 65 74 4c 61 75 6e 63 68 49 6e 74 65 6e 74 46 6f 72 50 61 63 6b 61 67 65 } //1 getLaunchIntentForPackage
		$a_01_6 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //1 setJavaScriptEnabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}