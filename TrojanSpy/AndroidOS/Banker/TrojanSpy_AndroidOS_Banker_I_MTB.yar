
rule TrojanSpy_AndroidOS_Banker_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 62 61 6e 61 6e 61 73 70 6c 69 74 2e 73 68 6f 70 } //1 api.bananasplit.shop
		$a_00_1 = {63 6f 6d 2f 6b 69 74 6b 61 67 61 6d 65 73 2f 66 61 6c 6c 62 75 64 64 69 65 73 } //1 com/kitkagames/fallbuddies
		$a_00_2 = {68 61 73 53 6d 73 53 65 72 76 69 63 65 73 } //1 hasSmsServices
		$a_00_3 = {6d 6f 62 69 6c 65 4e 75 6d 62 65 72 50 6f 72 74 61 62 6c 65 52 65 67 69 6f 6e 5f } //1 mobileNumberPortableRegion_
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_Banker_I_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 62 79 6c 2f 73 6d 73 2f 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //1 com/byl/sms/SplashActivity
		$a_00_1 = {38 38 38 63 63 62 2e 63 6f 6d 2f 61 70 69 2f 69 6e 64 65 78 2f 69 6e 66 6f 72 6d 61 74 69 6f 6e } //1 888ccb.com/api/index/information
		$a_00_2 = {73 68 61 6f 64 65 74 69 61 6e 6b 6f 6e 67 2e 63 6c 75 62 2f 61 70 69 2f 69 6e 64 65 78 2f 73 6d 73 } //1 shaodetiankong.club/api/index/sms
		$a_00_3 = {70 61 79 5f 70 61 73 73 77 6f 72 64 } //1 pay_password
		$a_00_4 = {4c 4f 47 49 4e 5f 43 48 45 43 4b 5f 49 53 50 41 53 53 } //1 LOGIN_CHECK_ISPASS
		$a_00_5 = {73 6d 53 41 70 70 6c 69 63 61 74 69 6f 6e } //1 smSApplication
		$a_00_6 = {75 70 6c 6f 61 64 53 6d 53 4d 65 74 68 6f 64 } //1 uploadSmSMethod
		$a_00_7 = {38 38 38 63 63 62 2e 63 6f 6d 2f 61 70 69 2f 69 6e 64 65 78 2f 73 6d 73 } //1 888ccb.com/api/index/sms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}