
rule Trojan_Linux_Melofee_A_MTB{
	meta:
		description = "Trojan:Linux/Melofee.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 6e ac 03 77 8b ae 56 7c a7 d6 24 e1 82 ec 31 e0 9f b9 f9 27 5a 8a e4 80 d7 60 5b 00 5f d3 1a 88 a9 49 4d 1d b7 c0 aa 4f 3e cc 20 99 a9 a7 fb 4e 5f 73 4a 6c 45 e1 e8 0e ac 3d 59 71 6d 20 c1 b9 18 3c d8 d4 7e 6d ba 5c 9c 63 bd c5 ab 1d d7 5b 38 5b 74 9b 99 95 b6 d0 9d 48 da 21 3f ae 40 } //1
		$a_01_1 = {5b 22 ce 1f 6b 8a 5d b3 85 ca be ec 23 0a 7e 31 c7 67 42 73 f1 28 bf 34 0f 32 40 55 6e 6b f0 25 8e 6e f7 f4 f9 31 d1 c4 cd df f3 f7 18 bb a0 d2 a6 d9 51 be 28 86 a8 bf 74 f4 58 2c 82 e1 0b ff c3 68 fc 40 33 62 27 65 0d ae 53 15 6b 09 53 ea 0c cd c8 61 51 01 ab 8d 4e 57 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}