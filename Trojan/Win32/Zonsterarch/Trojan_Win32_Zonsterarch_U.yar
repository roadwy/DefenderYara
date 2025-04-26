
rule Trojan_Win32_Zonsterarch_U{
	meta:
		description = "Trojan:Win32/Zonsterarch.U,SIGNATURE_TYPE_PEHSTR,14 00 14 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 74 6e 53 65 6e 64 53 6d 73 43 6c 69 63 6b } //10 btnSendSmsClick
		$a_01_1 = {61 6c 74 5f 70 61 79 5f 62 61 73 65 5f 75 72 6c } //10 alt_pay_base_url
		$a_01_2 = {62 74 6e 47 6f 57 65 62 50 61 79 6d 65 6e 74 43 6c 69 63 6b } //10 btnGoWebPaymentClick
		$a_01_3 = {7a 69 70 63 6f 6e 6e 65 63 74 2e 69 6e } //1 zipconnect.in
		$a_01_4 = {7a 69 70 2d 68 65 6c 70 2e 63 6f 6d } //1 zip-help.com
		$a_01_5 = {7a 69 70 6d 6f 6e 73 74 65 72 2e 72 75 2f 6d 61 69 6e } //1 zipmonster.ru/main
		$a_01_6 = {2f 2f 63 6f 75 6e 74 72 79 5b 40 63 69 64 3d 22 25 73 22 5d 2f 62 61 73 65 5b 40 63 6f 73 74 3d 22 25 73 22 5d 2f 70 72 69 63 65 5b 40 73 75 62 3d } //1 //country[@cid="%s"]/base[@cost="%s"]/price[@sub=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=20
 
}