
rule Trojan_MacOS_Amos_BY_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BY!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 03 16 aa 7f 01 00 94 f6 03 00 aa 60 00 00 b0 00 08 40 f9 61 00 00 90 21 54 3c 91 e2 00 80 52 8a 00 00 94 f7 03 00 aa c8 02 40 f9 08 09 40 f9 e0 03 16 aa 00 01 3f d6 f6 03 00 aa 86 01 00 94 e2 03 00 aa e0 03 17 aa e1 03 16 aa 7f 00 00 94 38 00 00 94 } //1
		$a_01_1 = {08 16 80 52 28 03 08 0a 83 02 15 8b 1f 81 00 71 62 00 94 9a 05 1f 00 13 e0 03 17 aa e1 03 14 aa e4 03 16 aa 2a 00 00 94 00 01 00 b5 68 02 40 f9 08 81 5e f8 60 02 08 8b 08 20 40 b9 a9 00 80 52 01 01 09 2a a8 00 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}