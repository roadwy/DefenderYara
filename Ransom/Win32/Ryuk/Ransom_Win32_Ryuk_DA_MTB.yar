
rule Ransom_Win32_Ryuk_DA_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6c 6f 63 6b 65 64 20 64 6f 77 6e } //1 Your system is locked down
		$a_81_1 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 64 65 63 72 79 70 74 } //1 Do not try to decrypt
		$a_81_2 = {6f 74 68 65 72 77 69 73 65 20 79 6f 75 20 77 69 6c 6c 20 64 61 6d 61 67 65 20 66 61 69 6c 73 } //1 otherwise you will damage fails
		$a_81_3 = {46 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 77 72 69 74 65 20 6f 6e 20 74 68 65 20 65 6d 61 69 6c } //1 For decryption tool write on the email
		$a_81_4 = {77 65 20 77 69 6c 6c 20 70 75 62 6c 69 73 68 20 61 6c 6c 20 70 72 69 76 61 74 65 20 64 61 74 61 20 6f 6e 20 68 74 74 70 3a 2f 2f 63 6f 6e 74 69 2e 6e 65 77 73 2f 54 45 53 54 } //1 we will publish all private data on http://conti.news/TEST
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=3
 
}