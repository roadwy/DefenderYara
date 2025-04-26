
rule Trojan_MacOS_Amos_CK_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CK!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 17 00 f9 e1 e3 00 91 21 78 60 f8 e1 1b 00 f9 e4 e3 00 94 5f e4 00 94 e0 1b 40 f9 e5 e5 00 94 00 e4 00 94 e0 17 40 f9 00 04 00 91 1f 40 00 f1 8b fe ff 54 } //1
		$a_01_1 = {90 0b 40 f9 ff 63 30 eb 49 03 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 5f 20 00 f1 e8 01 00 54 c2 01 00 b4 43 04 00 d1 5f 00 03 ea 61 01 00 54 3f 40 00 f1 c2 00 00 54 1b 00 80 39 00 0c 01 8b fd fb 7f a9 ff 83 00 91 c0 03 5f d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}