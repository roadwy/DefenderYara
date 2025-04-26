
rule Trojan_Win32_Drupirel_A{
	meta:
		description = "Trojan:Win32/Drupirel.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 00 68 00 65 00 75 00 72 00 6c 00 } //1 theurl
		$a_01_1 = {74 00 68 00 65 00 64 00 61 00 74 00 65 00 } //1 thedate
		$a_01_2 = {74 00 68 00 65 00 69 00 70 00 } //1 theip
		$a_01_3 = {72 00 65 00 70 00 69 00 70 00 } //1 repip
		$a_01_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //1 [InternetShortcut]
		$a_01_5 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 } //1 system32\drivers
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}