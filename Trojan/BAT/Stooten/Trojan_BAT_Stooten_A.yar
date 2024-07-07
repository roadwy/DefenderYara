
rule Trojan_BAT_Stooten_A{
	meta:
		description = "Trojan:BAT/Stooten.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 66 00 6c 00 6f 00 6f 00 64 00 } //1 httpflood
		$a_01_1 = {73 00 79 00 6e 00 66 00 6c 00 6f 00 6f 00 64 00 } //1 synflood
		$a_01_2 = {2f 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00 } //1 /connect.php
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}