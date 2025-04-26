
rule Trojan_MacOS_Amos_AE_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AE!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 1c 21 6e 20 83 86 3c e0 bf 47 fd 48 e6 01 0f 00 1c 28 2e e0 bf 07 fd 09 1f 00 12 56 06 80 52 29 01 16 4a e9 03 3e 39 e8 4b 02 f9 48 0a 80 52 e8 0b 09 79 48 a6 88 52 c8 aa a8 72 } //1
		$a_01_1 = {09 6a 82 52 b5 02 09 8b e8 03 02 f9 e1 23 10 91 e2 03 10 91 e0 03 15 aa c1 3e 00 94 e8 83 36 91 08 01 40 b2 c9 0a 80 52 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}