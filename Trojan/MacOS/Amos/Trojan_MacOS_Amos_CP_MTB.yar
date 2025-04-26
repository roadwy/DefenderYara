
rule Trojan_MacOS_Amos_CP_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CP!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c3 01 d1 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f6 03 01 aa f5 03 00 aa f4 03 08 aa 00 80 80 52 f9 01 00 94 f3 03 00 aa e1 1f 80 52 02 80 80 52 10 02 00 94 c8 5e c0 39 68 ?? ?? ?? 08 1d 40 92 e0 03 13 aa } //1
		$a_03_1 = {9f 7e 00 a9 9f 0a 00 f9 a8 5e 40 39 09 1d 00 13 aa 2e 40 a9 3f 01 00 71 59 b1 95 9a 69 b1 88 9a 49 ?? ?? ?? 1a 00 80 52 08 00 80 52 2a 03 09 8b ea 07 00 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}