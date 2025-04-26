
rule Trojan_MacOS_Amos_CG_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CG!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {e0 23 00 91 76 2a 00 94 e0 23 00 91 53 ff ff 97 1f 00 00 f1 e0 13 9f 5a a8 83 5c f8 69 00 00 b0 29 3d 40 f9 29 01 40 f9 3f 01 08 eb 41 ?? ?? ?? ff 43 08 91 fd 7b 43 a9 f4 4f 42 a9 f6 57 41 a9 f8 5f c4 a8 } //1
		$a_01_1 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f3 03 02 aa f5 03 01 aa f4 03 00 aa 97 00 00 b0 f7 42 0f 91 f8 02 40 f9 e0 03 17 aa 00 03 3f d6 08 00 40 39 96 00 00 b0 d6 e2 0e 91 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}