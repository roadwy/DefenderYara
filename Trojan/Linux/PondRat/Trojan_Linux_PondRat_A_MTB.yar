
rule Trojan_Linux_PondRat_A_MTB{
	meta:
		description = "Trojan:Linux/PondRat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 64 6b 67 72 61 64 6c 65 2e 63 6f 6d } //1 jdkgradle.com
		$a_01_1 = {31 c0 48 8b 5c 24 18 48 8b 6c 24 20 4c 8b 64 24 28 4c 8b 6c 24 30 4c 8b 74 24 38 4c 8b 7c 24 40 48 83 c4 48 c3 0f 1f 00 4c 89 ef e8 d0 e7 ff ff 31 c0 } //1
		$a_01_2 = {4c 89 ef e8 ed ec ff ff 31 c0 83 3b 00 0f 94 c0 48 81 c4 a0 01 00 00 5b 5d 41 5c 41 5d 41 5e c3 0f 1f 44 00 00 48 81 c4 a0 01 00 00 b8 01 00 00 00 5b 5d 41 5c 41 5d 41 5e c3 0f 1f 00 b9 40 89 84 00 ba 00 89 84 00 be 1d 1e 59 00 48 89 e7 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}