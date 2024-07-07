
rule Trojan_Win32_Vilsel_AP_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {84 3a 80 eb 25 c4 88 b8 00 41 90 f3 d7 69 04 a3 45 76 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 } //2
		$a_01_1 = {32 4e 5c 03 b9 93 b1 fd bc 34 93 fc a7 92 38 f1 } //2
		$a_01_2 = {54 00 68 00 69 00 73 00 20 00 70 00 6c 00 61 00 63 00 65 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 65 00 6e 00 6f 00 75 00 67 00 68 00 20 00 66 00 6f 00 72 00 20 00 75 00 73 00 20 00 21 00 } //1 This place is not enough for us !
		$a_01_3 = {52 00 65 00 73 00 74 00 20 00 49 00 6e 00 20 00 50 00 65 00 61 00 63 00 65 00 2e 00 2e 00 2e 00 20 00 50 00 65 00 73 00 69 00 6e 00 } //1 Rest In Peace... Pesin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}