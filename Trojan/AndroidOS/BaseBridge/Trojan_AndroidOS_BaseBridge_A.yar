
rule Trojan_AndroidOS_BaseBridge_A{
	meta:
		description = "Trojan:AndroidOS/BaseBridge.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 69 72 73 74 5f 61 70 70 5f 70 65 72 66 65 72 65 6e 63 65 73 } //1 first_app_perferences
		$a_01_1 = {62 61 74 74 65 72 79 2f 42 61 6c 63 6b 41 63 74 69 76 69 74 79 } //1 battery/BalckActivity
		$a_01_2 = {62 61 74 74 65 72 79 2f 42 61 73 65 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 battery/BaseBroadcastReceiver
		$a_01_3 = {62 61 74 74 65 72 79 2f 5a 6c 50 68 6f 6e 65 53 65 72 76 69 63 65 } //1 battery/ZlPhoneService
		$a_01_4 = {25 70 68 6f 6e 65 6e 75 6d 3d 3f 20 61 6e 64 20 6d 6f 75 74 68 63 6f 75 6e 74 3e 3d 6d 6f 75 74 68 74 69 6d 65 73 } //1 %phonenum=? and mouthcount>=mouthtimes
		$a_01_5 = {44 52 4f 50 20 54 41 42 4c 45 20 49 46 20 45 58 49 53 54 53 20 74 65 6c 70 68 6f 6e 65 } //1 DROP TABLE IF EXISTS telphone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}