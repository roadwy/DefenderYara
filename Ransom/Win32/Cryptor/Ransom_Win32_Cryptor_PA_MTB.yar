
rule Ransom_Win32_Cryptor_PA_MTB{
	meta:
		description = "Ransom:Win32/Cryptor.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 28 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 29 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files (documents, photos, videos) were encrypted
		$a_01_1 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //1 aaa_TouchMeNot_.txt
		$a_01_2 = {54 00 45 00 4d 00 50 00 5c 00 53 00 69 00 6d 00 70 00 6c 00 65 00 5f 00 45 00 6e 00 63 00 6f 00 64 00 65 00 72 00 5c 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 2e 00 6a 00 70 00 67 00 } //1 TEMP\Simple_Encoder\wallpaper.jpg
		$a_01_3 = {5f 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 53 00 2e 00 69 00 6e 00 69 00 } //1 _RECOVER_INSTRUCTIONS.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}