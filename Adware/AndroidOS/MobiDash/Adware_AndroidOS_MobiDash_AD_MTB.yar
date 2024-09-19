
rule Adware_AndroidOS_MobiDash_AD_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 72 6f 70 75 62 6c 69 63 61 } //1 com/propublica
		$a_01_1 = {70 72 6f 70 75 62 6c 69 63 61 2e 64 62 } //1 propublica.db
		$a_01_2 = {49 6e 74 65 72 73 74 69 74 69 61 6c 41 64 } //1 InterstitialAd
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}