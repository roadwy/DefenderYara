
rule Ransom_Win32_LockCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/LockCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 52 45 43 4f 56 45 52 2e 74 78 74 } //1 !RECOVER.txt
		$a_01_1 = {73 76 63 68 6f 73 74 32 } //1 svchost2
		$a_01_2 = {62 65 69 6a 69 6e 67 35 32 30 40 } //1 beijing520@
		$a_01_3 = {41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 57 41 53 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR DATA WAS ENCRYPTED
		$a_01_4 = {5f 5f 6c 6f 63 6b 5f 58 58 58 5f 5f } //1 __lock_XXX__
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}