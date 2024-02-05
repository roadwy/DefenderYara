
rule Trojan_Win32_Multsarch_N{
	meta:
		description = "Trojan:Win32/Multsarch.N,SIGNATURE_TYPE_PEHSTR,66 00 66 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //01 00 
		$a_01_1 = {74 6f 72 72 65 6e 74 5f 74 69 6d 65 72 } //01 00 
		$a_01_2 = {70 61 79 5f 73 6d 73 } //01 00 
		$a_01_3 = {73 6d 73 5f 6e 75 6d } //01 00 
		$a_01_4 = {73 74 65 70 5f 74 65 78 74 32 33 } //01 00 
		$a_01_5 = {75 c9 1c cd 5b 4e 72 0e 48 c3 53 de 5a 95 31 df ce 70 1f 5a d6 26 c9 bd c0 f0 e9 55 ac a7 98 bc 94 df bc f4 96 6f c9 65 ec } //00 00 
	condition:
		any of ($a_*)
 
}