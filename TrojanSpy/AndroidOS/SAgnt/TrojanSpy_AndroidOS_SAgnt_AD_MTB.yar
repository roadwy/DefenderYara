
rule TrojanSpy_AndroidOS_SAgnt_AD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 70 44 65 76 69 63 65 49 6e 66 6f } //1 upDeviceInfo
		$a_01_1 = {4c 63 6f 6d 2f 63 61 66 65 32 34 2f 68 6f 73 74 73 } //1 Lcom/cafe24/hosts
		$a_01_2 = {67 65 74 5f 73 6d 73 5f 69 6e 66 6f } //1 get_sms_info
		$a_01_3 = {75 70 43 6f 6e 74 61 63 74 73 } //1 upContacts
		$a_01_4 = {53 4d 53 5f 41 5f 55 } //1 SMS_A_U
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanSpy_AndroidOS_SAgnt_AD_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {79 6f 75 72 2d 61 70 70 2e 78 79 7a 2f 68 69 72 6f } //1 your-app.xyz/hiro
		$a_00_1 = {73 70 2e 6f 72 67 2e 68 74 74 70 75 74 69 6c 73 32 73 65 72 76 69 63 65 } //1 sp.org.httputils2service
		$a_00_2 = {73 70 2e 6f 72 67 2e 68 74 74 70 6a 6f 62 } //1 sp.org.httpjob
		$a_00_3 = {73 70 2e 6f 72 67 2e 70 6e 73 65 72 76 69 63 65 } //1 sp.org.pnservice
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}