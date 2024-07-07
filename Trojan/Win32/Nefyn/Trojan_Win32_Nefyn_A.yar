
rule Trojan_Win32_Nefyn_A{
	meta:
		description = "Trojan:Win32/Nefyn.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 00 73 00 75 00 00 00 25 00 74 00 65 00 6d 00 70 00 25 00 } //1
		$a_01_1 = {c6 44 24 10 46 c6 44 24 11 55 c6 44 24 12 43 c6 44 24 13 4b c6 44 24 14 54 c6 44 24 15 58 } //1
		$a_01_2 = {f3 a5 b9 33 00 00 00 8d bc 24 4c 03 00 00 f3 ab b9 41 00 00 00 8d bc 24 10 02 00 00 f3 ab b9 41 00 00 00 8d bc 24 0c 01 00 00 f3 ab b9 41 00 00 00 8d 7c 24 08 f3 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}