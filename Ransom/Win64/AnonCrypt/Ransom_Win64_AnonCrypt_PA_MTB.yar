
rule Ransom_Win64_AnonCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/AnonCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 6f 6e 2d 67 20 46 6f 78 } //3 Anon-g Fox
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 } //1 Go build ID
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //1 Your files have been encrypted successfully!
		$a_01_3 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 20 6f 6e 6c 79 20 72 75 6e 20 69 6e 20 49 73 72 61 65 6c 2e 65 78 65 } //1 This program can only run in Israel.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}