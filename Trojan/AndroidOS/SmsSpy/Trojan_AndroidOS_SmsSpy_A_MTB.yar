
rule Trojan_AndroidOS_SmsSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 61 79 2e 39 31 38 6a 61 2e 63 6f 6d } //2 pay.918ja.com
		$a_00_1 = {63 6f 6d 2e 64 79 6c 2e 70 61 79 2e 75 69 2e 61 70 6b } //1 com.dyl.pay.ui.apk
		$a_00_2 = {73 6d 73 5f 70 61 79 5f 6c 69 73 74 } //1 sms_pay_list
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}