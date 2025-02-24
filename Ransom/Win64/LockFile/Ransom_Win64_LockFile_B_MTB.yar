
rule Ransom_Win64_LockFile_B_MTB{
	meta:
		description = "Ransom:Win64/LockFile.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c8 48 89 44 24 58 45 8b 2c 0e 41 8b 5c 0e 04 41 0f cd 44 33 ac 24 00 01 00 00 0f cb 33 9c 24 f8 00 00 00 41 8b 6c 0e 08 0f cd 33 ac 24 f0 00 00 00 48 89 8c 24 08 01 00 00 41 8b 74 0e 0c 0f ce 33 b4 24 28 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}