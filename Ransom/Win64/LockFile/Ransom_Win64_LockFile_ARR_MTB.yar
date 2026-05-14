
rule Ransom_Win64_LockFile_ARR_MTB{
	meta:
		description = "Ransom:Win64/LockFile.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8a 04 0a 44 30 04 0f 4c 8d 41 ?? 4c 89 c1 4c 39 c3 } //10
		$a_01_1 = {66 41 0f fe d4 66 44 0f ef eb 66 0f ef f1 66 41 0f ef fe 66 45 0f 6f fe 66 0f ef c2 66 45 0f 6f f5 } //9
		$a_81_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //1 YOUR FILES HAVE BEEN ENCRYPTED!
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*9+(#a_81_2  & 1)*1) >=20
 
}