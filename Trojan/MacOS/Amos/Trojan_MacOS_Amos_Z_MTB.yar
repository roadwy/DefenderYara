
rule Trojan_MacOS_Amos_Z_MTB{
	meta:
		description = "Trojan:MacOS/Amos.Z!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 7f 40 39 09 1d 00 13 eb ab 40 a9 3f 01 00 71 53 b1 88 9a 74 b1 94 9a 68 06 00 91 1f 41 00 b1 22 07 00 54 1f 5d 00 f1 a2 00 00 54 f5 83 00 91 } //1
		$a_01_1 = {e8 3f c1 39 08 ff ff 36 e0 1f 40 f9 4c 00 00 94 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 ff 03 02 91 c0 03 5f d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}