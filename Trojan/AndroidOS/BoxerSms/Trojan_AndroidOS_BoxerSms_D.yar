
rule Trojan_AndroidOS_BoxerSms_D{
	meta:
		description = "Trojan:AndroidOS/BoxerSms.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 66 66 65 72 74 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //1 OffertActivity.java
		$a_01_1 = {53 63 68 65 64 75 6c 69 6e 67 20 72 65 67 69 73 74 72 61 74 69 6f 6e 20 72 65 74 72 79 2c 20 62 61 63 6b 6f 66 66 20 3d } //1 Scheduling registration retry, backoff =
		$a_01_2 = {50 41 59 45 44 5f 59 45 53 } //1 PAYED_YES
		$a_01_3 = {53 45 4e 44 45 44 5f 53 4d 53 5f 43 4f 55 4e 54 45 52 5f 4b 45 59 } //1 SENDED_SMS_COUNTER_KEY
		$a_01_4 = {4b 59 5f 49 44 } //1 KY_ID
		$a_03_5 = {73 6d 73 51 75 61 6e 74 69 74 79 [0-05] 73 6d 73 54 65 78 74 [0-05] 73 6d 73 5f 74 65 78 74 [0-05] 73 74 61 72 74 [0-05] 73 74 61 72 74 41 63 74 69 76 69 74 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}