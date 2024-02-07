
rule Trojan_Win32_Tarifarch_L{
	meta:
		description = "Trojan:Win32/Tarifarch.L,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6c 00 65 00 63 00 61 00 73 00 68 00 2e 00 72 00 75 00 } //01 00  filecash.ru
		$a_01_1 = {53 4d 53 4e 75 6d } //01 00  SMSNum
		$a_01_2 = {6d 65 50 68 6f 6e 65 4e 75 6d 62 65 72 } //00 00  mePhoneNumber
	condition:
		any of ($a_*)
 
}