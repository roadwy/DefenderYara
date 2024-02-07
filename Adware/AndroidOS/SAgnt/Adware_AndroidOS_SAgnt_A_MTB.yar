
rule Adware_AndroidOS_SAgnt_A_MTB{
	meta:
		description = "Adware:AndroidOS/SAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {6d 6f 62 70 61 72 6b 2f 63 6f 6d 2f 90 02 20 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 90 00 } //02 00 
		$a_01_1 = {4d 6f 62 50 61 72 6b 2e 61 70 6b } //02 00  MobPark.apk
		$a_01_2 = {67 65 74 49 6e 73 74 61 6c 6c 44 69 72 } //01 00  getInstallDir
		$a_01_3 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //01 00  InterstitialAd
		$a_01_4 = {70 6f 73 74 41 64 6d 6f 62 4c 6f 67 } //00 00  postAdmobLog
	condition:
		any of ($a_*)
 
}