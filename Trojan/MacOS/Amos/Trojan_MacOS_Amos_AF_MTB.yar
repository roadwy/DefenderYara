
rule Trojan_MacOS_Amos_AF_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AF!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ec 7f c1 39 ed 27 40 f9 6e 02 08 8b ce 05 40 39 2f 21 47 39 ce 01 0f 4a 9f 01 00 71 ac b1 8a 9a 8c 01 08 8b 8e 05 00 39 08 05 00 91 1f 01 0b eb 81 ?? ?? ?? 88 01 80 52 e8 1f 01 39 e8 e5 8d 52 88 0d af 72 e8 3b 00 b9 } //1
		$a_03_1 = {f6 73 40 f9 56 02 00 b4 e8 37 40 f9 08 19 40 f9 e0 03 14 aa 00 01 3f d6 f5 03 00 aa e0 03 16 aa 10 07 00 94 f6 03 00 aa ff 73 00 f9 e8 37 40 f9 08 0d 40 f9 e0 03 14 aa 01 00 80 d2 02 00 80 d2 00 01 3f d6 c8 02 15 2a 08 ?? ?? ?? e8 33 40 f9 08 81 5e f8 e9 83 01 91 20 01 08 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}