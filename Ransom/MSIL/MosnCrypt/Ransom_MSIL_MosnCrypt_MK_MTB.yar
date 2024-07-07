
rule Ransom_MSIL_MosnCrypt_MK_MTB{
	meta:
		description = "Ransom:MSIL/MosnCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {49 4e 46 4f 52 4d 41 54 49 4f 4e 5f 52 45 41 44 5f 4d 45 2e 74 78 74 } //INFORMATION_READ_ME.txt  1
		$a_80_1 = {46 49 4c 45 53 2d 45 4e 43 52 59 50 54 45 44 3a } //FILES-ENCRYPTED:  1
		$a_80_2 = {48 41 52 44 57 41 52 45 2d 49 44 5f 49 4e 43 4c 55 44 45 5f 49 4e 5f 4d 41 49 4c 3a } //HARDWARE-ID_INCLUDE_IN_MAIL:  1
		$a_80_3 = {45 4e 43 52 59 50 54 45 44 5f 4d 45 4d 4f 52 59 5f 53 54 52 49 4e 47 53 } //ENCRYPTED_MEMORY_STRINGS  1
		$a_80_4 = {45 6e 63 72 79 70 74 41 6c 6c 46 69 6c 65 73 } //EncryptAllFiles  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}