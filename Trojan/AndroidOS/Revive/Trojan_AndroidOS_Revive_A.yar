
rule Trojan_AndroidOS_Revive_A{
	meta:
		description = "Trojan:AndroidOS/Revive.A,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 4b 65 79 4c 69 73 74 65 72 } //10 startKeyLister
		$a_00_1 = {72 65 61 64 4b 65 79 4c 6f 67 } //10 readKeyLog
		$a_00_2 = {6b 65 79 6c 6f 67 5f 74 61 62 6c 65 } //10 keylog_table
		$a_00_3 = {67 65 74 4b 65 79 4c 6f 67 73 } //10 getKeyLogs
		$a_00_4 = {2f 73 6d 73 2f 69 6e 73 65 72 74 } //1 /sms/insert
		$a_00_5 = {2f 6b 65 79 6c 6f 67 2f 69 6e 73 65 72 74 } //1 /keylog/insert
		$a_00_6 = {53 6d 73 52 65 63 69 76 65 72 } //1 SmsReciver
		$a_00_7 = {6b 65 79 6c 6f 67 67 65 72 } //1 keylogger
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=12
 
}