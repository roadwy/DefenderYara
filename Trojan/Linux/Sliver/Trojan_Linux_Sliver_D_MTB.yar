
rule Trojan_Linux_Sliver_D_MTB{
	meta:
		description = "Trojan:Linux/Sliver.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 89 44 24 08 73 37 49 8d 7e 10 4c 89 f6 ff 15 a9 6a 2c 00 48 8b 14 24 eb 2f 48 89 c1 48 c1 e9 3d 0f 85 9b 02 00 00 48 c1 e0 03 48 83 f8 0e 0f 83 37 01 00 00 6a 01 41 5e e9 56 01 00 00 f3 41 0f 6f 06 f3 41 0f 7f 04 16 31 ed 4d 89 f5 } //1
		$a_00_1 = {8b 17 85 d2 7e 24 8d 4a ff 31 c0 83 fa 01 75 0b 8b 47 04 85 c0 0f 95 c0 0f b6 c0 29 c1 89 d0 f0 0f b1 0f 39 c2 75 d9 31 c0 c3 50 e8 80 36 ff ff c7 00 0b 00 00 00 83 c8 ff 5a c3 } //1
		$a_00_2 = {4c 89 e7 31 f6 e8 4a b7 ff ff 4c 89 e0 41 5c c3 0f 1f 80 00 00 00 00 48 85 d2 74 e4 0f b6 06 41 88 04 24 84 c0 74 d9 48 83 ea 01 48 83 c6 01 49 83 c4 01 40 f6 c6 07 75 de 48 85 d2 74 c2 80 3e 00 74 bd 49 b9 ff fe fe fe fe fe fe fe 49 b8 80 80 80 80 80 80 80 80 48 83 fa 07 77 24 eb 96 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}