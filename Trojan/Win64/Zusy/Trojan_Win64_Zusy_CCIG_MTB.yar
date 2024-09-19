
rule Trojan_Win64_Zusy_CCIG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.CCIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 44 4d 7a 59 54 56 6a 4e 54 63 32 4f 54 5a 6c 4e 6a 51 32 5a 6a 63 33 4e 7a 4d 31 59 7a 55 7a 4e 7a 6b 33 4d 7a 63 30 4e 6a 55 32 5a 44 4d 7a 4d 7a 49 31 59 77 3d 3d } //1 NDMzYTVjNTc2OTZlNjQ2Zjc3NzM1YzUzNzk3Mzc0NjU2ZDMzMzI1Yw==
		$a_01_1 = {4e 44 67 30 59 6a 51 7a 4e 54 55 7a 59 54 56 6a 4e 54 4d 32 5a 6a 59 32 4e 7a 51 33 4e 7a 59 78 4e 7a 49 32 4e 54 56 6a 4e 44 4d 32 59 7a 59 78 4e 7a 4d 33 4d 7a 59 31 4e 7a 4d 31 59 7a 4a 6c 4e 7a 63 33 4d 7a 63 32 4e 6a 4d 31 59 77 3d 3d } //1 NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzJlNzc3Mzc2NjM1Yw==
		$a_01_2 = {4e 54 4d 32 4f 44 59 31 4e 6d 4d 32 59 7a 56 6a 4e 47 59 33 4d 44 59 31 4e 6d 55 31 59 7a 59 7a 4e 6d 59 32 5a 44 5a 6b 4e 6a 45 32 5a 54 59 30 } //1 NTM2ODY1NmM2YzVjNGY3MDY1NmU1YzYzNmY2ZDZkNjE2ZTY0
		$a_01_3 = {4e 44 67 30 59 6a 51 7a 4e 54 55 7a 59 54 56 6a 4e 54 4d 32 5a 6a 59 32 4e 7a 51 33 4e 7a 59 78 4e 7a 49 32 4e 54 56 6a 4e 44 4d 32 59 7a 59 78 4e 7a 4d 33 4d 7a 59 31 4e 7a 4d 31 59 7a 5a 6b 4e 7a 4d 79 5a 44 63 7a 4e 6a 55 33 4e 44 63 30 4e 6a 6b 32 5a 54 59 33 4e 7a 4d 31 59 7a 51 7a 4e 7a 55 33 4d 6a 55 32 4e 6a 55 33 4d 67 3d 3d } //1 NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1YzQzNzU3MjU2NjU3Mg==
		$a_01_4 = {4e 6a 59 32 5a 6a 59 30 4e 6a 67 32 4e 54 5a 6a 4e 7a 41 32 4e 54 63 79 } //1 NjY2ZjY0Njg2NTZjNzA2NTcy
		$a_01_5 = {4e 44 67 30 59 6a 51 7a 4e 54 55 7a 59 54 56 6a 4e 54 4d 32 5a 6a 59 32 4e 7a 51 33 4e 7a 59 78 4e 7a 49 32 4e 54 56 6a 4e 44 4d 32 59 7a 59 78 4e 7a 4d 33 4d 7a 59 31 4e 7a 4d 31 59 7a 5a 6b 4e 7a 4d 79 5a 44 63 7a 4e 6a 55 33 4e 44 63 30 4e 6a 6b 32 5a 54 59 33 4e 7a 4d 31 59 77 3d 3d } //1 NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1Yw==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}