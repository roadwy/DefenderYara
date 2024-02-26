
rule Trojan_AndroidOS_FakeInst_J_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 63 6f 6d 6d 6f 6e 61 75 74 6f 73 65 6e 64 } //01 00  _commonautosend
		$a_01_1 = {62 65 6c 6f 72 75 73 5f 6c 69 6e 6b 65 64 5f 74 65 78 74 5f 32 } //01 00  belorus_linked_text_2
		$a_01_2 = {42 45 4c 4c 4f 52 55 53 53 5f 49 44 } //01 00  BELLORUSS_ID
		$a_01_3 = {46 49 52 53 54 5f 4d 54 53 5f 53 45 4e 44 5f 31 30 } //01 00  FIRST_MTS_SEND_10
		$a_01_4 = {63 6f 6d 2e 67 6f 6f 67 6c 65 61 70 70 73 2e 72 75 } //01 00  com.googleapps.ru
		$a_01_5 = {53 45 4e 54 5f 53 4d 53 5f 43 4f 55 4e 54 5f 4b 45 59 } //00 00  SENT_SMS_COUNT_KEY
	condition:
		any of ($a_*)
 
}