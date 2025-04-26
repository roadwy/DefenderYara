
rule Ransom_Linux_FastCrypt_A_MTB{
	meta:
		description = "Ransom:Linux/FastCrypt.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 50 61 73 74 65 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 main.PasteRansomNote
		$a_01_1 = {46 61 73 74 43 72 79 70 74 46 69 6c 65 73 } //1 FastCryptFiles
		$a_01_2 = {6d 61 69 6e 2e 43 72 79 70 74 41 6c 6c 44 69 73 6b } //1 main.CryptAllDisk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}