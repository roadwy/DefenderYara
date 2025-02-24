
rule Ransom_Win64_LockFile_D_MTB{
	meta:
		description = "Ransom:Win64/LockFile.D!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 21 48 8b 85 f8 06 00 00 8b 08 ba 6b 6e 69 67 31 d1 0f b7 40 04 35 68 74 00 00 09 c8 } //1
		$a_01_1 = {48 8b 85 e0 07 00 00 0f b6 8d e8 07 00 00 88 8d 56 08 00 00 48 89 85 f8 07 00 00 48 8d 48 10 } //1
		$a_01_2 = {48 89 44 24 20 48 c7 44 24 40 00 00 00 00 48 89 f9 31 d2 45 31 c0 45 31 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}