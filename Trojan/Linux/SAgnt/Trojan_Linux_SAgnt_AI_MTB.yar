
rule Trojan_Linux_SAgnt_AI_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.AI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {ff 07 40 d1 00 00 00 90 ff 03 11 d1 00 c0 36 91 fd 7b bd a9 fd 03 00 91 f5 5b 02 a9 f6 03 01 aa 01 00 80 52 f3 53 01 a9 d6 ff ff 97 40 00 00 35 a4 ff ff 97 bf 7f 05 a9 40 00 80 52 a0 a3 00 79 00 00 00 90 13 00 00 90 00 00 37 91 } //1
		$a_01_1 = {02 00 82 d2 01 00 80 52 a0 c3 11 91 57 ff ff 97 e0 03 13 2a 5d ff ff 97 c0 02 40 f9 a1 c3 01 91 7e ff ff 97 00 00 00 90 a1 c3 01 91 22 00 80 52 00 b4 37 91 3d ff ff 97 a0 83 01 91 a0 1f 00 f9 82 00 00 b0 00 00 00 90 a1 1f 40 f9 00 c4 37 91 42 60 41 f9 20 00 00 f9 e0 03 14 2a 3f 04 00 f9 } //1
		$a_01_2 = {83 e4 f0 ff 71 fc 55 89 e5 57 56 53 51 81 ec 70 14 00 00 8b 41 04 89 85 94 eb ff ff 6a 00 68 60 8a 04 08 e8 54 ff ff ff 83 c4 10 85 c0 75 0a 83 ec 0c 6a 00 e8 d3 fe ff ff b8 21 00 00 00 8d bd c7 eb ff ff 89 c1 be 8c 8a 04 08 f3 a4 } //1
		$a_01_3 = {89 d7 31 c0 b9 00 04 00 00 83 ec 0c f3 ab 53 8d 9d e8 eb ff ff e8 0d fe ff ff 58 8b 85 94 eb ff ff 5a 53 ff 30 e8 3d fd ff ff 83 c4 0c 6a 01 53 68 79 8a 04 08 e8 4d fd ff ff 83 c4 0c 8d 85 ac eb ff ff ff 35 d8 9c 04 08 50 56 c7 85 ac eb ff ff 7d 8a 04 08 } //1
		$a_01_4 = {2d e9 f0 41 ad f5 a1 5d 82 b0 0f 46 4b 48 00 21 ff f7 ba ef 08 b9 ff f7 94 ef 06 a8 00 21 10 22 ff f7 a6 ef 02 23 ad f8 18 30 45 4b 45 48 1b 68 ad f8 1a 30 } //1
		$a_01_5 = {4f f4 80 52 00 21 28 46 ff f7 36 ef 20 46 ff f7 6a ef 0a a9 38 68 ff f7 60 ef 0a a9 01 22 0e 48 ff f7 1e ef 0d 4b 40 46 04 a9 04 93 00 23 05 93 0b 4b 1a 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}