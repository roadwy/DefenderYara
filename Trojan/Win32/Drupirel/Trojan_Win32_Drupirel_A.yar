
rule Trojan_Win32_Drupirel_A{
	meta:
		description = "Trojan:Win32/Drupirel.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 68 00 65 00 75 00 72 00 6c 00 } //01 00  theurl
		$a_01_1 = {74 00 68 00 65 00 64 00 61 00 74 00 65 00 } //01 00  thedate
		$a_01_2 = {74 00 68 00 65 00 69 00 70 00 } //01 00  theip
		$a_01_3 = {72 00 65 00 70 00 69 00 70 00 } //01 00  repip
		$a_01_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_01_5 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 } //00 00  system32\drivers
	condition:
		any of ($a_*)
 
}