
rule Ransom_Linux_Conti_A{
	meta:
		description = "Ransom:Linux/Conti.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {4d 49 49 43 43 41 4b 43 41 67 45 41 39 66 41 33 75 76 4d 73 53 42 56 30 70 57 75 39 66 56 59 4e 63 38 7a 58 48 42 65 35 6d 41 44 61 4a 35 39 64 65 65 63 63 61 43 42 41 67 59 35 54 } //01 00  MIICCAKCAgEA9fA3uvMsSBV0pWu9fVYNc8zXHBe5mADaJ59deeccaCBAgY5T
		$a_00_1 = {2d 2d 76 6d 6b 69 6c 6c 65 72 } //01 00  --vmkiller
		$a_00_2 = {2d 2d 70 72 6f 63 6b 69 6c 6c 65 72 } //01 00  --prockiller
		$a_00_3 = {70 61 72 65 6d 65 74 65 72 20 2d 2d 73 69 7a 65 20 63 61 6e 6e 6f 74 20 62 65 20 25 64 } //02 00  paremeter --size cannot be %d
		$a_00_4 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 4f 4e 54 49 20 73 74 72 61 69 6e } //01 00  All of your files are currently encrypted by CONTI strain
		$a_01_5 = {48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 89 d1 48 29 c1 48 89 c8 48 01 c0 48 89 45 a8 48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 03 48 01 d0 48 01 c0 48 89 45 b0 e9 ae 03 00 00 } //01 00 
		$a_01_6 = {48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 89 45 a8 48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 89 45 b0 eb 0a } //00 00 
		$a_00_7 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}