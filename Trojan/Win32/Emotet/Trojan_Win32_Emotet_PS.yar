
rule Trojan_Win32_Emotet_PS{
	meta:
		description = "Trojan:Win32/Emotet.PS,SIGNATURE_TYPE_PEHSTR,28 00 28 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {31 c9 41 83 ec 04 c1 e1 05 81 f9 98 00 00 00 } //0a 00 
		$a_01_1 = {81 cb 81 3a 00 00 43 46 81 ce 01 40 00 40 } //0a 00 
		$a_01_2 = {81 f1 b1 c2 ef 3c } //0a 00 
		$a_01_3 = {68 91 7f 09 00 68 de 7e d9 00 } //0a 00 
		$a_01_4 = {68 9f c3 79 00 } //0a 00 
		$a_01_5 = {68 ee fb 58 00 } //00 00 
		$a_01_6 = {00 5d 04 00 00 e8 c4 03 80 5c 2c 00 00 e9 c4 03 80 00 00 01 00 08 00 16 00 54 72 6f 6a 61 } //6e 3a 
	condition:
		any of ($a_*)
 
}