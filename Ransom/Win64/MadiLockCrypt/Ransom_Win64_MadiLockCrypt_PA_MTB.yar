
rule Ransom_Win64_MadiLockCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/MadiLockCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4d 61 64 69 4c 6f 63 6b } //3 .MadiLock
		$a_01_1 = {52 45 41 44 4d 45 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 46 49 4c 45 53 21 21 21 2e 74 78 74 } //1 README_TO_RECOVER_FILES!!!.txt
		$a_01_2 = {46 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 73 74 6f 6c 65 6e 2e 20 50 61 79 20 74 6f 20 64 65 63 72 79 70 74 20 61 6e 64 20 64 65 6c 65 74 65 20 73 74 6f 6c 65 6e 20 63 6f 70 69 65 73 } //1 Files were encrypted and stolen. Pay to decrypt and delete stolen copies
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}