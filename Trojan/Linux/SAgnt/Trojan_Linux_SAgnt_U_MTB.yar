
rule Trojan_Linux_SAgnt_U_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.U!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 d2 45 85 ed 41 51 49 89 d8 6a 00 0f 95 c2 4c 89 e1 45 31 c9 48 c1 e2 07 48 89 ee bf ca 00 00 00 e8 41 b5 ff ff 41 5a 41 5b 83 f8 da 75 1e 56 49 89 d8 bf ca 00 00 00 45 31 c9 6a 00 4c 89 e1 31 d2 48 89 ee } //1
		$a_01_1 = {4c 89 ff 4c 89 e1 48 8d 15 10 e5 00 00 31 c0 be 80 10 00 00 e8 e2 5f 00 00 4c 89 ff e8 0c 52 00 00 4c 89 f2 4c 89 ee 4c 89 e7 e8 8c 50 00 00 e9 2d ff ff ff 66 0f 1f 84 00 00 00 00 00 4c 89 e6 4c 89 ff e8 a5 8c 00 00 48 85 c0 0f 85 ac 00 00 00 31 d2 be 80 10 00 00 4c 89 ff e8 b8 58 00 00 48 85 c0 75 d8 31 ff } //1
		$a_01_2 = {41 0f b6 4f 01 b8 00 03 00 00 41 02 0f d3 e0 49 8b 77 08 8d 88 c0 07 00 00 48 85 c9 0f 84 a5 00 00 00 48 8d 41 ff 48 83 f8 06 0f 86 fd 02 00 00 48 89 ca 66 0f 6f 05 c5 b3 00 00 48 89 f0 48 c1 ea 03 48 c1 e2 04 48 01 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}