
rule Ransom_Linux_Babyk_C_MTB{
	meta:
		description = "Ransom:Linux/Babyk.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //01 00 
		$a_00_1 = {48 8b 45 f8 0f b6 40 12 3c 08 75 77 48 8b 45 f8 48 83 c0 13 be 7b b8 40 00 48 89 c7 e8 18 fa ff ff 48 85 c0 74 5d 48 8b 55 d8 48 8b 45 e8 48 89 d6 48 89 c7 e8 50 fa ff ff 48 8b 45 e8 be 79 b8 40 00 48 89 c7 e8 ff f9 ff ff 48 8b 45 f8 48 8d 50 13 48 8b 45 e8 48 89 d6 48 89 c7 e8 e8 f9 ff ff 48 8b 45 e8 48 89 c6 bf 82 b8 40 00 b8 00 00 00 00 e8 f2 f8 ff ff 48 8b 45 e8 48 89 c7 } //01 00 
		$a_00_2 = {48 8b 55 d8 48 8b 45 e0 48 89 d1 ba 00 00 a0 00 be 01 00 00 00 48 89 c7 e8 a2 fc ff ff 48 89 45 c8 48 8b 45 c8 48 01 45 c0 48 83 7d c8 00 0f 84 86 00 00 00 48 8b 4d c8 48 8b 55 e0 48 8b 5d e0 48 8d 85 60 fe ff ff 48 89 de 48 89 c7 e8 8b a7 00 00 48 8b 45 c8 48 f7 d8 48 89 c1 48 8b 45 d8 ba 01 00 00 00 48 89 ce 48 89 c7 e8 7f fb ff ff 48 8b 4d d8 48 8b 55 c8 48 8b 45 e0 be 01 00 00 00 48 89 c7 e8 96 fc ff ff 48 81 7d c0 ff ff ff 1f } //00 00 
	condition:
		any of ($a_*)
 
}