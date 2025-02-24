
rule Trojan_MacOS_Amos_CF_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CF!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c3 03 d1 f8 5f 0b a9 f6 57 0c a9 f4 4f 0d a9 fd 7b 0e a9 fd 83 03 91 b5 83 01 d1 00 0a 80 52 0b 02 00 94 f3 03 00 aa a0 83 1b f8 08 00 00 b0 00 ad c2 3d a0 02 82 3c 08 00 00 b0 08 99 2b 91 00 05 40 ad 00 04 00 ad 00 05 41 ad 00 04 01 ad 1f 00 01 39 } //1
		$a_01_1 = {1f f0 00 39 e8 43 01 91 a0 83 01 d1 c9 fe ff 97 e8 e3 00 91 e0 43 01 91 a1 23 01 d1 08 fe ff 97 e8 83 00 91 e0 a3 01 91 c2 fe ff 97 f6 23 00 91 e8 23 00 91 e0 83 00 91 a1 23 01 d1 00 fe ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}