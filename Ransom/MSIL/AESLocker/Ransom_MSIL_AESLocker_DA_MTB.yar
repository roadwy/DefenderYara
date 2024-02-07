
rule Ransom_MSIL_AESLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/AESLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 45 53 2d 4c 6f 63 6b 65 72 } //01 00  AES-Locker
		$a_81_1 = {45 6e 63 72 79 70 74 4b 65 79 } //01 00  EncryptKey
		$a_81_2 = {45 6e 63 72 79 70 74 41 45 53 } //01 00  EncryptAES
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //01 00  .locked
		$a_81_4 = {2e 69 61 73 6b 2e 69 6e } //01 00  .iask.in
		$a_81_5 = {6c 6f 63 6b 2e 74 78 74 } //00 00  lock.txt
	condition:
		any of ($a_*)
 
}