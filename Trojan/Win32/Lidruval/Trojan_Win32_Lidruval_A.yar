
rule Trojan_Win32_Lidruval_A{
	meta:
		description = "Trojan:Win32/Lidruval.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 03 f9 8a 17 32 d0 88 17 2b f9 41 c1 e8 08 e2 ef } //1
		$a_01_1 = {83 f8 23 75 59 8b 4d fc c6 01 23 8b 55 fc 83 c2 01 89 55 fc 8b 45 08 03 45 f8 33 c9 8a 08 } //1
		$a_03_2 = {68 30 20 00 00 68 90 01 04 8d 95 90 01 02 ff ff 52 6a 00 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}