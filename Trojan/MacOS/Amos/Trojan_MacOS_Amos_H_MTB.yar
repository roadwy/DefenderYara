
rule Trojan_MacOS_Amos_H_MTB{
	meta:
		description = "Trojan:MacOS/Amos.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {eb 31 4d 89 f4 49 83 cc 0f 49 8d 7c 24 01 e8 f2 3a 00 00 48 89 43 10 49 83 c4 02 4c 89 23 4c 89 73 08 48 89 c3 48 89 df 4c 89 fe 4c 89 f2 e8 92 3b 00 00 42 c6 04 33 00 } //1
		$a_00_1 = {74 34 0f 57 c0 48 8b 51 f8 49 89 57 f8 0f 10 49 e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 41 e8 48 c7 41 f8 00 00 00 00 48 8d 51 e8 48 89 d1 48 39 c2 75 d3 4c 89 7d e0 48 8d 7d b8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}