
rule Trojan_AndroidOS_SAgnt_AF_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 6e 73 66 6f 72 6d 53 4d 53 } //1 transformSMS
		$a_01_1 = {67 65 74 44 65 76 69 63 65 44 65 74 61 69 6c 73 } //1 getDeviceDetails
		$a_01_2 = {53 6d 73 52 65 63 65 69 76 65 72 48 65 6c 70 65 72 } //1 SmsReceiverHelper
		$a_01_3 = {72 6f 6f 6d 69 6e 67 5f 6e 65 74 77 6f 72 6b } //1 rooming_network
		$a_01_4 = {72 65 71 75 65 73 74 46 69 72 73 74 53 6d 73 } //1 requestFirstSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}