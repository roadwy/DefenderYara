
rule Trojan_AndroidOS_SmsThief_FK{
	meta:
		description = "Trojan:AndroidOS/SmsThief.FK,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 6e 6e 6e 2e 6c 69 76 65 2f 61 70 69 2e 70 68 70 } //2 mnnn.live/api.php
		$a_01_1 = {6e 6f 6f 72 61 7a 2f 54 68 69 72 64 41 63 74 69 76 69 74 79 } //2 nooraz/ThirdActivity
		$a_01_2 = {6e 62 70 2d 77 65 62 2e 6d 79 61 70 70 2e 72 75 2e 63 6f 6d } //2 nbp-web.myapp.ru.com
		$a_01_3 = {62 6f 70 64 69 67 69 74 61 6c 2f 4d 79 52 65 63 65 69 76 65 72 } //2 bopdigital/MyReceiver
		$a_01_4 = {59 6f 75 72 20 72 65 71 75 65 73 74 20 69 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 75 62 6d 69 74 74 65 64 2e 57 65 20 74 72 79 20 74 6f 20 6f 70 74 69 6d 69 7a 65 20 79 6f 75 72 20 61 63 63 6f 75 6e 74 2e 49 74 20 6d 61 79 20 74 61 6b 65 20 61 20 66 65 77 20 68 6f 75 72 73 20 6f 72 20 64 61 79 73 } //2 Your request is successfully submitted.We try to optimize your account.It may take a few hours or days
		$a_01_5 = {69 6e 73 74 61 62 72 6f 77 73 65 72 2f 73 65 6e 64 53 6d 73 54 6f 53 65 72 76 65 72 } //2 instabrowser/sendSmsToServer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=4
 
}