
rule Trojan_MacOS_Amos_CD_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CD!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa 08 00 40 f9 08 81 5e f8 00 00 08 8b 41 01 80 52 96 04 00 94 e1 03 00 aa e0 03 13 aa e6 04 00 94 e0 03 13 aa e7 04 00 94 e0 03 13 aa fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6 } //1
		$a_01_1 = {fd 7b bf a9 fd 03 00 91 00 01 80 52 03 05 00 94 ba 04 00 94 61 00 00 d0 21 1c 40 f9 62 00 00 d0 42 08 40 f9 09 05 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}