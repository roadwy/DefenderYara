
rule Ransom_Win32_CrazyCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/CrazyCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 61 7a 79 43 72 79 70 74 5f 45 6e 63 72 79 70 74 } //01 00  CrazyCrypt_Encrypt
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files have been encrypted
		$a_81_2 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } //01 00  /C choice /C Y /N /D Y /T 3 & Del "
		$a_81_3 = {59 6f 75 72 20 70 72 69 76 61 74 65 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 64 65 73 74 72 6f 79 65 64 } //00 00  Your private key will be destroyed
	condition:
		any of ($a_*)
 
}