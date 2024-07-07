
rule Trojan_AndroidOS_Smsthief_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Smsthief.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4d 65 73 73 61 67 65 3f 70 61 72 73 65 5f 6d 6f 64 65 3d 6d 61 72 6b 64 6f 77 6e 26 63 68 61 74 5f 69 64 3d } //1 sendMessage?parse_mode=markdown&chat_id=
		$a_01_1 = {6c 6f 6b 65 74 32 2d 66 61 73 74 70 61 79 2e 6f 6e 6c 69 6e 65 } //1 loket2-fastpay.online
		$a_01_2 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e } //1 com/example/myapplication
		$a_01_3 = {53 65 6e 64 53 4d 53 } //1 SendSMS
		$a_01_4 = {52 65 63 65 69 76 65 53 6d 73 } //1 ReceiveSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}