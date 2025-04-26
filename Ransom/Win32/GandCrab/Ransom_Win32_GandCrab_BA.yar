
rule Ransom_Win32_GandCrab_BA{
	meta:
		description = "Ransom:Win32/GandCrab.BA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {5a 61 73 7a 79 66 72 6f 77 61 6e 65 50 6c 69 6b 69 } //1 ZaszyfrowanePliki
		$a_00_1 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 AesCryptoServiceProvider
		$a_00_2 = {72 65 67 69 73 74 72 79 20 69 73 20 66 75 63 6b 65 64 } //1 registry is fucked
		$a_80_3 = {66 69 6c 65 73 20 61 72 65 20 69 6e 66 65 63 74 65 64 } //files are infected  1
		$a_80_4 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //files have been encrypted  1
		$a_80_5 = {77 68 6f 5f 61 63 63 65 70 74 73 5f 62 69 74 63 6f 69 6e 73 5f 61 73 5f 70 61 79 6d 65 6e 74 } //who_accepts_bitcoins_as_payment  1
		$a_80_6 = {62 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //bitcoin to this address  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=3
 
}