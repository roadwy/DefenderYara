
rule Ransom_Linux_RagnarLocker_B_MTB{
	meta:
		description = "Ransom:Linux/RagnarLocker.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 52 45 41 44 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 } //01 00  .README_TO_RESTORE
		$a_00_1 = {46 69 6c 65 20 4c 6f 63 6b 65 64 3a 25 73 20 50 49 44 3a 25 64 } //01 00  File Locked:%s PID:%d
		$a_00_2 = {2e 63 72 79 70 74 65 64 } //01 00  .crypted
		$a_00_3 = {77 72 6b 6d 61 6e 2e 6c 6f 67 } //01 00  wrkman.log
		$a_00_4 = {55 73 61 67 65 3a 25 73 20 5b 2d 6d 20 28 31 30 2d 32 30 2d 32 35 2d 33 33 2d 35 30 29 20 5d 20 53 74 61 72 74 20 50 61 74 68 } //01 00  Usage:%s [-m (10-20-25-33-50) ] Start Path
		$a_03_5 = {48 8b 3d bc 90 01 01 20 00 48 85 ff 74 11 ba 92 01 00 00 be 90 01 04 31 c0 e8 90 01 02 fe ff 48 8b 3d 9f 90 01 01 20 00 e8 90 01 02 fe ff 45 31 ed 48 83 c9 ff 48 89 df 44 88 e8 f2 ae 48 f7 d1 44 8d 61 1f 4d 63 e4 4c 89 e7 e8 90 01 02 fe ff 4c 89 e1 48 89 c5 48 89 c7 44 88 e8 48 89 da be 48 ed 41 00 f3 aa b9 90 01 04 48 89 ef 90 00 } //01 00 
		$a_03_6 = {48 89 e0 80 30 5c 48 ff c0 4c 39 e0 75 90 01 01 ba 40 00 00 00 48 89 ee e8 90 01 02 ff ff c7 03 67 e6 09 6a c7 43 04 85 ae 67 bb 48 89 e8 c7 43 08 72 f3 6e 3c c7 43 0c 3a f5 4f a5 c7 43 10 7f 52 0e 51 c7 43 14 8c 68 05 9b c7 43 18 ab d9 83 1f c7 43 1c 19 cd e0 5b 48 c7 43 60 00 00 00 00 80 30 6a 48 ff c0 4c 39 e0 75 90 01 01 48 89 ee 90 00 } //01 00 
		$a_03_7 = {55 31 ed 89 e8 53 48 81 ec e8 01 00 00 48 8d 7c 24 0c 48 c7 04 24 41 00 00 00 4c 8d 64 24 0c f3 ab 48 8d 7c 24 2c b1 08 f3 ab 48 8d 7c 24 4c b1 08 f3 ab 48 8d bc 24 ec 00 00 00 b1 3d f3 ab bf 01 03 00 00 e8 90 01 02 ff ff 48 85 c0 48 89 c3 75 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}