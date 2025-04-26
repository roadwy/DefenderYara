
rule Trojan_AndroidOS_SAgnt_AD_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 46 75 6e 63 74 69 6f 6e } //1 SMSFunction
		$a_01_1 = {53 61 76 65 50 68 6f 6e 65 54 65 78 74 } //1 SavePhoneText
		$a_01_2 = {43 68 65 63 6b 53 65 6e 64 4c 69 73 74 } //1 CheckSendList
		$a_01_3 = {72 65 61 64 52 65 63 6f 72 64 73 } //1 readRecords
		$a_01_4 = {4f 70 65 6e 57 45 42 } //1 OpenWEB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}