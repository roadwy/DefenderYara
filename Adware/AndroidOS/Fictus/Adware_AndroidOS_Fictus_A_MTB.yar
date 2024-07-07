
rule Adware_AndroidOS_Fictus_A_MTB{
	meta:
		description = "Adware:AndroidOS/Fictus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 70 6b 66 69 6c 65 73 2e 63 6f 6d 2f 61 70 6b 2d 32 34 38 35 32 2f 61 72 2d 63 6c 65 61 6e 65 72 2f } //1 apkfiles.com/apk-24852/ar-cleaner/
		$a_01_1 = {63 6f 6d 2f 61 70 70 2f 61 74 74 61 63 6b 65 72 2f 67 6f 6f 64 77 6f 72 6b } //1 com/app/attacker/goodwork
		$a_01_2 = {6d 6f 62 69 6c 65 61 64 73 } //1 mobileads
		$a_01_3 = {41 64 44 69 73 70 6c 61 79 4c 69 73 74 65 6e 65 72 } //1 AdDisplayListener
		$a_01_4 = {6c 6f 61 64 41 64 73 } //1 loadAds
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}