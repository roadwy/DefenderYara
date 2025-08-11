
rule Trojan_Linux_SAgnt_Z_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.Z!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3b a3 00 14 39 00 00 00 38 e0 ff ff 38 c0 00 22 38 a0 00 03 7f a4 eb 78 38 60 00 00 48 00 03 45 60 00 00 00 2c 23 ff ff 7c 7e 1b 78 41 82 ff c8 4b ff f3 29 4b ff f3 79 4b ff f4 31 7c 7f 1b 79 40 82 00 28 60 00 00 00 38 62 89 10 48 00 61 d1 60 00 00 00 7f a4 eb 78 7f c3 f3 78 48 00 04 65 } //1
		$a_01_1 = {3b c0 00 02 39 00 00 00 38 e0 ff ff e9 22 85 a0 38 c0 00 22 38 a0 00 00 38 60 00 00 7f de 48 36 7c 9f f1 d2 48 00 0c 29 60 00 00 00 2c 23 ff ff 41 82 fe d8 60 00 00 00 7c 63 fa 14 3b de ff ff f8 62 85 b8 7b e9 a3 02 7f de 49 d2 60 00 00 00 fb c2 85 98 e9 22 85 a0 39 29 00 01 f9 22 85 a0 } //1
		$a_01_2 = {39 03 00 01 55 0a f8 7e 55 09 f0 be 7d 29 53 78 55 2a f0 be 7d 29 53 78 55 2a e1 3e 7d 29 53 78 55 2a c2 3e 7d 29 53 78 55 2a 84 3e 7d 29 53 78 39 49 00 01 7d 49 48 78 3d 40 07 6b 61 4a e6 29 7d 29 51 d6 3d 42 ff fe 39 4a a3 18 79 29 2e e2 7c 6a 48 ae 3d 42 ff fe 39 4a a2 b8 38 63 ff ff 54 63 10 3a 39 23 00 01 7d 29 07 b4 79 29 0f a4 7d 2a 4a 2e 7c 29 40 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}