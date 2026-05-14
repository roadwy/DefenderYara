
rule Ransom_Win64_LockDownCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/LockDownCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 4f 43 4b 44 4f 57 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } //3 LOCKDOWN RANSOMWARE
		$a_01_1 = {2e 63 72 79 70 74 5f 6c 6f 63 6b } //1 .crypt_lock
		$a_01_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files are encrypted
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}