
rule Ransom_MSIL_AESLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/AESLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 45 53 2d 4c 6f 63 6b 65 72 } //1 AES-Locker
		$a_81_1 = {45 6e 63 72 79 70 74 4b 65 79 } //1 EncryptKey
		$a_81_2 = {45 6e 63 72 79 70 74 41 45 53 } //1 EncryptAES
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_4 = {2e 69 61 73 6b 2e 69 6e } //1 .iask.in
		$a_81_5 = {6c 6f 63 6b 2e 74 78 74 } //1 lock.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}