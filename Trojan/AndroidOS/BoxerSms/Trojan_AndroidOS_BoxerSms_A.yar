
rule Trojan_AndroidOS_BoxerSms_A{
	meta:
		description = "Trojan:AndroidOS/BoxerSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 0a 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 4f 66 66 65 72 74 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //1 ReadOffertActivity.java
		$a_01_1 = {46 75 75 75 75 75 21 21 } //1 Fuuuuu!!
		$a_01_2 = {45 72 72 6f 72 20 72 65 61 64 69 6e 67 20 73 6d 73 2e 63 66 67 } //1 Error reading sms.cfg
		$a_01_3 = {64 65 70 6f 73 69 74 6d 6f 62 69 } //1 depositmobi
		$a_01_4 = {73 65 6e 64 65 64 53 6d 73 43 6f 75 6e 74 65 72 } //1 sendedSmsCounter
		$a_01_5 = {69 5f 64 69 73 61 67 72 65 65 5f 6f 66 66 65 72 74 } //1 i_disagree_offert
		$a_01_6 = {69 5f 61 63 63 65 70 74 5f 6f 66 66 65 72 74 } //1 i_accept_offert
		$a_01_7 = {72 65 61 64 5f 6f 66 66 65 72 74 5f 62 75 74 74 6f 6e } //1 read_offert_button
		$a_01_8 = {6e 65 65 64 53 65 6e 64 65 64 54 6f 41 63 74 69 76 61 74 65 } //1 needSendedToActivate
		$a_01_9 = {6d 61 69 6e 5f 6f 66 66 65 72 74 5f 74 65 78 74 } //1 main_offert_text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}