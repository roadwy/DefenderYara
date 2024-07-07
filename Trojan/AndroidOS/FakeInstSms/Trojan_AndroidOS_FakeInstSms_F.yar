
rule Trojan_AndroidOS_FakeInstSms_F{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.F,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 45 4e 54 5f 53 4d 53 5f 43 4f 55 4e 54 5f 4b 45 59 } //1 SENT_SMS_COUNT_KEY
		$a_00_1 = {49 4e 53 54 41 4c 4c 4c 45 44 5f 54 45 58 54 5f 54 41 47 } //1 INSTALLLED_TEXT_TAG
		$a_02_2 = {42 45 4c 4c 4f 52 55 53 53 5f 49 44 90 02 15 42 57 43 5f 49 44 90 00 } //1
		$a_00_3 = {6e 73 35 72 75 5f 6d } //1 ns5ru_m
		$a_00_4 = {61 63 74 5f 73 63 68 65 6d 65 73 } //1 act_schemes
		$a_00_5 = {63 6e 74 72 79 54 61 67 } //1 cntryTag
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}