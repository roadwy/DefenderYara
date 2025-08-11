
rule Ransom_Win64_LockCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/LockCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //1 READ_TO_DECRYPT.txt
		$a_01_1 = {2f 75 70 6c 6f 61 64 5f 73 74 6f 6c 65 6e 2e 70 68 70 } //1 /upload_stolen.php
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //2 YOUR FILES HAVE BEEN ENCRYPTED!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}