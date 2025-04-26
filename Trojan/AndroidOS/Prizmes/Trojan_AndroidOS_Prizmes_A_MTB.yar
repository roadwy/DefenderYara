
rule Trojan_AndroidOS_Prizmes_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Prizmes.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 53 65 6e 64 53 6d 73 53 65 72 76 69 63 65 } //1 AutoSendSmsService
		$a_01_1 = {43 54 65 6c 65 70 68 6f 6e 65 49 6e 66 6f } //1 CTelephoneInfo
		$a_01_2 = {64 74 2e 73 7a 70 72 69 7a 65 2e 63 6e 2f 6d 62 69 6e 66 6f 2e 70 68 70 } //1 dt.szprize.cn/mbinfo.php
		$a_01_3 = {69 6e 74 65 72 63 65 70 74 53 6d 73 52 65 63 69 65 76 65 72 } //1 interceptSmsReciever
		$a_01_4 = {75 70 64 61 74 65 54 69 6d 65 73 4f 66 53 6d 73 } //1 updateTimesOfSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}