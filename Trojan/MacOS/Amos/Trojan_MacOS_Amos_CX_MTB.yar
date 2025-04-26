
rule Trojan_MacOS_Amos_CX_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CX!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c3 01 d1 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 7b 06 a9 fd 83 01 91 f4 03 00 aa f3 03 08 aa 08 5c c0 39 a8 ?? ?? ?? 09 1d 00 12 e9 ?? ?? ?? 08 1d 40 92 } //1
		$a_03_1 = {89 a2 40 a9 0a f9 40 92 55 05 00 d1 3f 01 15 eb a1 ?? ?? ?? e9 ef 7d b2 5f 01 09 eb a0 ?? ?? ?? 13 fd 78 d3 96 02 40 f9 a8 01 80 92 e8 ff e7 f2 bf 02 08 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}