
rule Trojan_AndroidOS_Smsthief_B{
	meta:
		description = "Trojan:AndroidOS/Smsthief.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 6c 69 65 6e 74 41 64 76 61 6e 63 65 64 } //2 getClientAdvanced
		$a_01_1 = {63 6f 6d 2e 65 61 73 79 6c 69 6e 7a 2e 72 65 6c 6f 61 64 } //2 com.easylinz.reload
		$a_01_2 = {70 68 6f 6e 65 4d 67 72 } //2 phoneMgr
		$a_01_3 = {51 75 69 63 6b 52 65 73 70 6f 6e 73 65 53 65 72 76 69 63 65 24 53 6d 73 52 65 63 65 69 76 65 72 } //2 QuickResponseService$SmsReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}