
rule Ransom_Win32_Gocrypt_YA_MTB{
	meta:
		description = "Ransom:Win32/Gocrypt.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 72 61 6e 73 6f 6d 77 61 72 65 2f 63 6c 69 65 6e 74 } //1 /ransomware/client
		$a_01_1 = {46 49 4c 45 53 5f 45 4e 43 52 59 50 54 45 44 2e 68 74 6d 6c 44 65 73 6b 74 6f 70 5c 52 45 41 44 5f 54 4f 5f 44 45 43 52 59 50 54 2e 68 74 6d 6c } //1 FILES_ENCRYPTED.htmlDesktop\READ_TO_DECRYPT.html
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}