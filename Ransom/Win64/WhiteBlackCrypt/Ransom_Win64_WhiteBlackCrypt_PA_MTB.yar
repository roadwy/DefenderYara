
rule Ransom_Win64_WhiteBlackCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/WhiteBlackCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 72 70 74 33 64 } //3 .encrpt3d
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 43 68 65 63 6b 53 65 72 76 69 63 65 44 2e 65 78 65 } //2 C:\ProgramData\CheckServiceD.exe
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 45 4e 43 52 59 50 54 45 44 21 } //2 Your files has been ENCRYPTED!
		$a_01_3 = {57 68 69 74 65 62 6c 61 63 6b 67 72 6f 75 70 30 30 32 40 67 6d 61 69 6c 2e 63 6f 6d } //1 Whiteblackgroup002@gmail.com
		$a_01_4 = {57 62 67 72 6f 75 70 30 32 32 40 67 6d 61 69 6c 2e 63 6f 6d } //1 Wbgroup022@gmail.com
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}