
rule Trojan_Win32_Misector_A{
	meta:
		description = "Trojan:Win32/Misector.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 72 65 74 61 69 6c 5c 70 6f 73 5c 42 69 6f 43 65 72 74 46 69 6c 65 73 5c 42 69 6f 65 72 74 50 61 74 68 32 2e 72 65 67 } //01 00  \retail\pos\BioCertFiles\BioertPath2.reg
		$a_01_1 = {73 75 6e 73 65 6e 67 25 63 25 63 25 69 2e 25 69 2e 25 69 2e 7a 69 70 } //01 00  sunseng%c%c%i.%i.%i.zip
		$a_01_2 = {6f 77 6e 65 6d 61 69 6c } //01 00  ownemail
		$a_01_3 = {64 75 67 72 61 73 40 73 65 6e 64 73 70 61 63 65 2e 63 6f 6d } //01 00  dugras@sendspace.com
		$a_01_4 = {72 65 63 70 65 6d 61 69 6c } //01 00  recpemail
		$a_01_5 = {76 61 6c 65 72 69 73 74 61 72 40 65 31 2e 72 75 } //00 00  valeristar@e1.ru
	condition:
		any of ($a_*)
 
}