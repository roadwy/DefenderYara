
rule Trojan_MacOS_Amos_DF_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DF!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 e0 07 00 f9 86 00 00 94 e8 07 40 f9 01 01 40 f9 1f 01 00 f9 10 00 00 94 e8 07 40 f9 08 05 40 f9 00 01 3f d6 e0 23 00 91 0d 00 00 94 00 00 80 d2 fd 7b 42 a9 f4 4f 41 a9 ff c3 00 91 c0 03 5f d6 } //1
		$a_01_1 = {fc 6f bd a9 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 09 36 82 52 90 00 00 90 10 22 40 f9 00 02 3f d6 ff 07 40 d1 ff c3 06 d1 01 00 00 90 21 10 07 91 a0 a3 00 d1 d7 0a 00 94 01 00 00 f0 21 cc 27 91 a0 03 01 d1 bd 0a 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}