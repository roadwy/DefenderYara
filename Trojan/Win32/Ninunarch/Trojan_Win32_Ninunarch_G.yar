
rule Trojan_Win32_Ninunarch_G{
	meta:
		description = "Trojan:Win32/Ninunarch.G,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 39 31 31 2e 72 75 } //10 sms911.ru
		$a_01_1 = {77 00 69 00 6e 00 72 00 61 00 72 00 2e 00 69 00 63 00 6f 00 } //10 winrar.ico
		$a_01_2 = {73 75 70 70 6f 72 74 2e 70 68 70 } //1 support.php
		$a_01_3 = {66 6c 65 78 69 62 69 6c 6c 2e 72 75 2f 70 72 69 63 65 } //1 flexibill.ru/price
		$a_01_4 = {73 6d 73 39 31 31 5f 63 6c 69 63 6b 65 64 28 29 } //1 sms911_clicked()
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=22
 
}