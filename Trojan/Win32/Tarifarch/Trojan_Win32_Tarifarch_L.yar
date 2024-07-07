
rule Trojan_Win32_Tarifarch_L{
	meta:
		description = "Trojan:Win32/Tarifarch.L,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6c 00 65 00 63 00 61 00 73 00 68 00 2e 00 72 00 75 00 } //10 filecash.ru
		$a_01_1 = {53 4d 53 4e 75 6d } //1 SMSNum
		$a_01_2 = {6d 65 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 mePhoneNumber
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}