
rule Trojan_MacOS_Amos_CJ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CJ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 83 00 91 a1 e3 00 d1 15 ff ff 97 e8 7f c0 39 e9 07 40 f9 1f 01 00 71 20 b1 96 9a 77 00 00 94 e8 3f c1 39 e9 1f 40 f9 1f 01 00 71 e8 e3 00 91 20 b1 88 9a 71 00 00 94 e8 7f c0 39 68 02 f8 37 e8 df c0 39 } //1
		$a_01_1 = {f6 03 00 aa e8 9f c1 39 28 02 f8 37 12 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa 10 00 00 14 f6 03 00 aa e8 7f c0 39 28 02 f8 37 e8 df c0 39 68 02 f8 37 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}