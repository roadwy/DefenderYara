
rule Trojan_Linux_SAgnt_Q_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.Q!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {be a8 12 60 00 55 48 81 ee a8 12 60 00 48 c1 fe 03 48 89 e5 48 89 f0 48 c1 e8 3f 48 01 c6 48 d1 fe 74 15 b8 00 00 00 00 48 85 c0 74 0b 5d bf a8 12 60 00 ff e0 0f 1f 00 5d c3 66 0f 1f 44 00 00 80 3d a9 06 20 00 00 75 11 55 48 89 e5 e8 6e ff ff ff 5d c6 05 96 06 20 00 01 f3 c3 0f 1f 40 00 bf 10 10 60 00 48 83 3f 00 75 05 eb 93 0f 1f 00 b8 00 00 00 00 48 85 c0 74 f1 55 48 89 e5 ff d0 5d e9 7a ff ff ff } //1
		$a_00_1 = {e8 00 ff ff ff ff c0 75 0c bf 0a 00 00 00 e8 02 ff ff ff eb df 31 c9 ba 06 00 00 00 be e4 0c 40 00 89 df e8 2d fe ff ff 66 8b 44 24 1e 48 8d 74 24 02 31 c9 ba 02 00 00 00 89 df 88 44 24 02 66 c1 e8 08 88 44 24 03 e8 09 fe ff ff 48 8d 74 24 2f 31 c9 ba 20 00 00 00 89 df e8 f6 fd ff ff 31 d2 31 c0 be eb 0c 40 00 bf 3f 01 00 00 e8 43 fe ff ff 85 c0 41 89 c4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}