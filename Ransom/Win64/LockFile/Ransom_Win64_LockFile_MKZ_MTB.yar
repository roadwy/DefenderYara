
rule Ransom_Win64_LockFile_MKZ_MTB{
	meta:
		description = "Ransom:Win64/LockFile.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 da 41 8d 43 15 48 d3 ea 44 89 c1 31 d0 48 89 da 48 d3 ea 83 f0 aa 44 31 da c1 e0 08 41 83 c3 2a 83 f2 aa 0f b6 d2 09 d0 66 43 33 04 02 66 43 89 04 01 49 83 c0 02 41 80 fb 13 75 be } //5
		$a_01_1 = {45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //1 ENCRYPTED
		$a_01_2 = {52 00 45 00 43 00 4f 00 56 00 45 00 52 00 59 00 } //1 RECOVERY
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}