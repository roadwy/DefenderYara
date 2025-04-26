
rule Trojan_AndroidOS_SMSSend_A_xp{
	meta:
		description = "Trojan:AndroidOS/SMSSend.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 61 70 69 2e 68 65 6a 75 70 61 79 2e 63 6f 6d 2f 67 65 74 53 6d 73 53 65 6e 64 2e 70 68 70 } //1 smsapi.hejupay.com/getSmsSend.php
		$a_00_1 = {53 74 61 72 74 53 6d 73 50 61 79 5d } //1 StartSmsPay]
		$a_00_2 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_00_3 = {63 6d 63 63 2f 67 2f 6f 6e 6c 69 6e 65 2f 73 32 73 41 75 74 6f 43 68 61 72 67 65 53 4d 53 3f 74 61 73 6b 49 64 3d 24 74 61 73 6b 49 64 26 70 69 64 3d 24 70 69 64 26 76 65 72 73 69 6f 6e 3d 24 76 65 72 73 69 6f 6e } //2 cmcc/g/online/s2sAutoChargeSMS?taskId=$taskId&pid=$pid&version=$version
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2) >=4
 
}