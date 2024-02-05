
rule Ransom_Linux_IceFire_A_MTB{
	meta:
		description = "Ransom:Linux/IceFire.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 69 46 69 72 65 2d 72 65 61 64 6d 65 2e 74 78 74 } //01 00 
		$a_00_1 = {2e 69 46 69 72 65 } //01 00 
		$a_00_2 = {2e 2f 62 6f 6f 74 2e 2f 64 65 76 2e 2f 65 74 63 2e 2f 6c 69 62 2e 2f 70 72 6f 63 2e 2f 73 72 76 2e 2f 73 79 73 2e 2f 75 73 72 2e 2f 76 61 72 2e 2f 72 75 6e } //01 00 
		$a_00_3 = {0f a2 41 89 c3 31 c0 81 fb 47 65 6e 75 0f 95 c0 41 89 c1 81 fa 69 6e 65 49 0f 95 c0 41 09 c1 81 f9 6e 74 65 6c 0f 95 c0 41 09 c1 0f 84 87 00 00 00 81 fb 41 75 74 68 0f 95 c0 41 89 c2 81 fa 65 6e 74 69 0f 95 c0 41 09 c2 81 f9 63 41 4d 44 0f 95 c0 41 09 c2 } //01 00 
		$a_00_4 = {c6 45 a0 29 c6 45 a1 c0 c6 45 a2 f6 c6 45 a3 94 c6 45 a4 fd c6 45 a5 fd c6 45 a6 fd c6 45 a7 fd c6 45 a8 43 c6 45 a9 6f c6 45 aa 6d c6 45 ab 53 c6 45 ac 70 c6 45 ad 65 c6 45 ae 63 c6 45 af 3d c6 45 b0 43 c6 45 b1 3a c6 45 b2 5c c6 45 b3 57 c6 45 b4 69 c6 45 b5 6e c6 45 b6 64 c6 45 b7 6f c6 45 b8 77 c6 45 b9 73 c6 45 ba 5c c6 45 bb 73 c6 45 bc 79 c6 45 bd 73 c6 45 be 74 c6 45 bf 65 } //00 00 
	condition:
		any of ($a_*)
 
}