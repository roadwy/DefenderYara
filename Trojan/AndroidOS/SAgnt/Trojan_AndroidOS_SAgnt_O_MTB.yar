
rule Trojan_AndroidOS_SAgnt_O_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 73 6d 73 5f 74 69 6d 65 6f 75 74 } //1 send_sms_timeout
		$a_01_1 = {50 68 6f 6e 65 53 74 61 72 53 65 72 76 69 63 65 } //1 PhoneStarService
		$a_01_2 = {73 6d 73 72 64 6f } //1 smsrdo
		$a_01_3 = {43 61 6c 6c 50 68 6f 6e 65 55 74 69 6c } //1 CallPhoneUtil
		$a_01_4 = {64 65 6c 65 74 53 6d 73 } //1 deletSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}