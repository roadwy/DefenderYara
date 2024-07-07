
rule Trojan_Win32_Hioles_B{
	meta:
		description = "Trojan:Win32/Hioles.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f9 c7 00 15 fb a4 68 c7 40 04 a0 65 b5 55 } //1
		$a_01_1 = {8b 14 11 03 d1 03 d0 c1 ca 03 41 8b c2 3b 4c 24 08 72 e9 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}