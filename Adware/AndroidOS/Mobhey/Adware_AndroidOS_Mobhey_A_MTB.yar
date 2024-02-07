
rule Adware_AndroidOS_Mobhey_A_MTB{
	meta:
		description = "Adware:AndroidOS/Mobhey.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 64 2e 6d 61 69 6c 2e 72 75 2f 6d 6f 62 69 6c 65 2f } //01 00  ad.mail.ru/mobile/
		$a_01_1 = {63 6f 6d 2f 63 6f 6f 74 65 6b 2f 69 63 6f 6e 66 61 63 65 } //01 00  com/cootek/iconface
		$a_01_2 = {63 6f 6d 2f 6d 79 2f 74 61 72 67 65 74 2f 61 64 73 2f 4d 79 54 61 72 67 65 74 41 63 74 69 76 69 74 79 } //01 00  com/my/target/ads/MyTargetActivity
		$a_01_3 = {54 72 61 63 65 72 41 63 74 69 76 69 74 79 4c 69 66 65 63 79 63 6c 65 43 61 6c 6c 62 61 63 6b } //00 00  TracerActivityLifecycleCallback
	condition:
		any of ($a_*)
 
}