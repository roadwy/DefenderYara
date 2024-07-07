
rule Trojan_Win32_Zonidel_A{
	meta:
		description = "Trojan:Win32/Zonidel.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 75 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //1 AutoUpdateDisableNotify
		$a_01_1 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //1 FirewallDisableNotify
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 6c 70 73 72 67 70 73 72 68 6f 6a 69 66 64 69 6a 2e 72 75 2f } //1 http://slpsrgpsrhojifdij.ru/
		$a_01_3 = {68 74 74 70 3a 2f 2f 39 32 2e 36 33 2e 31 39 37 2e 34 38 2f } //1 http://92.63.197.48/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}