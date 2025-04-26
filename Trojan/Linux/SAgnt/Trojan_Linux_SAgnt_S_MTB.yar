
rule Trojan_Linux_SAgnt_S_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.S!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 c9 ba 00 10 00 00 48 89 ee 89 df e8 08 fd ff ff 85 c0 48 89 c2 89 c1 7e 21 48 89 e8 80 30 99 48 ff c0 89 c6 29 ee 39 ce 7c f2 48 63 d2 48 89 ee 44 89 ef } //1
		$a_01_1 = {31 c0 b9 00 04 00 00 48 89 ef f3 ab 89 df e8 1b fd ff ff 49 8b 3c 24 48 8d b4 24 30 08 00 00 31 c0 e8 78 fd ff ff 48 8d b4 24 30 08 00 00 ba 01 00 00 00 bf 52 0e 40 00 31 c0 e8 bf fc ff ff 48 8b 15 d8 06 20 00 48 8d 74 24 10 44 89 ef 31 c0 48 c7 44 24 10 56 0e 40 00 48 c7 44 24 18 00 00 00 00 e8 07 fd ff ff 89 df e8 c0 fc ff ff 48 81 c4 38 1c 00 00 31 c0 5b 5d 41 5c 41 5d c3 } //1
		$a_01_2 = {66 44 8b 4c 24 22 41 b8 c5 0d 40 00 66 41 c1 c9 08 45 0f b7 c9 48 89 ef b9 a4 0d 40 00 41 51 68 a4 0d 40 00 ba c9 0d 40 00 be cd 0d 40 00 31 c0 e8 a7 fe ff ff 31 c9 ba 00 04 00 00 48 89 ee 89 df e8 f6 fd ff ff 31 c0 48 89 ef b9 00 01 00 00 f3 ab 31 ed 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}