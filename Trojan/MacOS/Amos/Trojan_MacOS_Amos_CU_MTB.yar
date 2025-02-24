
rule Trojan_MacOS_Amos_CU_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CU!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7f 7e 00 a9 7f 0a 00 f9 01 fd 41 d3 e0 03 13 aa 8b 01 00 94 16 00 80 d2 17 00 80 d2 58 00 80 52 f9 23 00 91 03 00 00 14 } //1
		$a_01_1 = {ff c3 01 d1 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f4 03 00 aa f3 03 08 aa 08 5c c0 39 a8 00 f8 37 09 1d 00 12 e9 06 00 37 08 1d 40 92 03 00 00 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}