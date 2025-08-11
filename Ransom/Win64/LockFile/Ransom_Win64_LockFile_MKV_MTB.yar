
rule Ransom_Win64_LockFile_MKV_MTB{
	meta:
		description = "Ransom:Win64/LockFile.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0b 33 d2 49 8b c0 48 f7 73 10 0f b6 0c 0a 48 8d 45 e7 48 83 7d ?? 0f 48 0f 47 45 e7 42 30 0c 00 49 ff c0 4c 3b 45 f7 72 } //5
		$a_81_1 = {59 4f 55 52 20 53 59 53 54 45 4d 20 49 53 20 4c 4f 43 4b 45 44 21 } //1 YOUR SYSTEM IS LOCKED!
		$a_81_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_81_3 = {44 45 43 52 59 50 54 5f 4f 52 5f 4c 4f 53 45 5f 45 56 45 52 59 54 48 49 4e 47 } //1 DECRYPT_OR_LOSE_EVERYTHING
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=8
 
}