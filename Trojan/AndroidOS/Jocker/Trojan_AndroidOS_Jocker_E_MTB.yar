
rule Trojan_AndroidOS_Jocker_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Jocker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6c 6f 61 64 65 72 2e 6c 6f 63 6b } //1 taskloader.lock
		$a_01_1 = {64 78 2d 61 64 73 2e 73 33 2e 75 73 2d 65 61 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d } //1 dx-ads.s3.us-east-2.amazonaws.com
		$a_01_2 = {63 6f 6d 2e 74 68 69 72 64 2e 41 } //1 com.third.A
		$a_01_3 = {63 64 6e 2e 68 65 61 6c 74 68 63 68 65 63 6b 65 72 6f 75 74 2e 63 6f 6d } //1 cdn.healthcheckerout.com
		$a_01_4 = {74 6f 4e 6f 74 69 66 69 63 61 74 69 6f 6e 53 65 74 74 69 6e 67 73 55 49 } //1 toNotificationSettingsUI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}