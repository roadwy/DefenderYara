
rule Trojan_Win32_Fidjito_A{
	meta:
		description = "Trojan:Win32/Fidjito.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 37 8d 44 24 14 6a 00 50 57 53 56 } //1
		$a_01_1 = {b3 6c 52 c6 44 24 20 73 c6 44 24 21 66 c6 44 24 22 63 } //1
		$a_01_2 = {8d 44 24 0c 50 6a 04 56 6a 09 53 c7 06 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}