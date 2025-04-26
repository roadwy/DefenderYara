
rule Trojan_MacOS_Amos_BZ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BZ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c8 02 40 f9 e0 03 16 aa 00 01 3f d6 e1 03 00 aa 38 00 80 52 18 e8 00 39 48 00 00 f0 08 b1 06 91 00 05 40 ad 00 04 00 ad 00 09 c0 3d 00 08 80 3d 00 a1 c2 3c 00 a0 82 3c 00 00 00 b0 00 d0 02 91 e2 ff ff b0 42 00 00 91 e9 28 00 94 e0 03 15 aa e0 02 3f d6 18 00 00 39 } //1
		$a_01_1 = {a8 02 40 f9 e0 03 15 aa 00 01 3f d6 e1 03 00 aa 37 00 80 52 17 08 00 39 28 f7 88 52 08 00 00 79 00 00 00 b0 00 f0 01 91 e2 ff ff b0 42 00 00 91 8d 2a 00 94 e0 03 14 aa c0 02 3f d6 17 00 00 39 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}