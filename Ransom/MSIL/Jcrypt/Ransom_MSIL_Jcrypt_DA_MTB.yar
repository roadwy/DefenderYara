
rule Ransom_MSIL_Jcrypt_DA_MTB{
	meta:
		description = "Ransom:MSIL/Jcrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_81_1 = {2e 6a 63 72 79 70 74 } //1 .jcrypt
		$a_81_2 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //1 RECOVER__FILES
		$a_81_3 = {41 46 54 45 52 20 50 41 59 4d 45 4e 54 20 49 53 20 53 45 4e 54 20 59 4f 55 52 20 46 49 4c 45 53 20 57 49 4c 4c 20 42 45 20 44 45 43 52 59 50 54 45 44 } //1 AFTER PAYMENT IS SENT YOUR FILES WILL BE DECRYPTED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}