
rule Trojan_MacOS_Amos_DG_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DG!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {cb ff ff 97 a0 00 00 35 f3 07 00 f9 e0 23 00 91 04 00 00 94 fb ff ff 17 } //1
		$a_01_1 = {ab 5e 40 39 6a 1d 00 13 ac 06 40 f9 5f 01 00 71 8b b1 8b 9a 1f 01 0b eb 02 01 00 54 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 4a 69 68 38 28 79 2a b8 08 05 00 91 f3 ff ff 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}