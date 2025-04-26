
rule Trojan_AndroidOS_FakeInst_C_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 41 66 74 65 72 53 74 61 72 74 } //1 sendAfterStart
		$a_00_1 = {72 61 77 2f 73 6d 73 2e 78 6d 6c } //1 raw/sms.xml
		$a_00_2 = {63 61 74 63 68 53 6d 73 } //1 catchSms
		$a_00_3 = {4c 63 6f 6d 2f 6c 6f 61 64 2f 77 61 70 2f 53 6d 73 52 65 63 69 76 65 72 } //1 Lcom/load/wap/SmsReciver
		$a_00_4 = {72 65 6d 6f 76 65 41 6c 6c 53 6d 73 46 69 6c 74 65 72 73 } //1 removeAllSmsFilters
		$a_00_5 = {73 65 6e 64 43 6f 6e 74 61 63 74 4c 69 73 74 } //1 sendContactList
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}