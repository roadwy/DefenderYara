
rule Ransom_Win32_Sorena_SK_MTB{
	meta:
		description = "Ransom:Win32/Sorena.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 4c 6f 63 6b 65 64 21 } //1 All Your Files Has Been Locked!
		$a_01_1 = {3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 20 48 61 63 6b 20 46 6f 72 20 53 65 63 75 72 69 74 79 } //1 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Hack For Security
		$a_01_2 = {43 3a 2f 55 73 65 72 73 2f 41 44 4d 49 4e 2f 67 6f 2f 73 63 72 2f 45 6e 63 72 79 70 74 2f 45 6e 63 72 79 70 74 2e 67 6f } //1 C:/Users/ADMIN/go/scr/Encrypt/Encrypt.go
		$a_01_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}