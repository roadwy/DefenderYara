
rule Ransom_Win64_IndustrialSpy_MA_MTB{
	meta:
		description = "Ransom:Win64/IndustrialSpy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 55 6e 64 65 72 67 72 6f 75 6e 64 20 74 65 61 6d 20 77 65 6c 63 6f 6d 65 73 20 79 6f 75 21 } //1 The Underground team welcomes you!
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 2c 20 74 68 65 79 20 63 61 6e 20 62 65 20 72 65 73 74 6f 72 65 64 20 74 6f 20 74 68 65 69 72 20 6f 72 69 67 69 6e 61 6c 20 73 74 61 74 65 20 77 69 74 68 20 61 20 64 65 63 72 79 70 74 6f 72 20 6b 65 79 20 74 68 61 74 20 6f 6e 6c 79 20 77 65 20 68 61 76 65 } //1 Your files are currently encrypted, they can be restored to their original state with a decryptor key that only we have
		$a_01_2 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 72 65 63 6f 76 65 72 20 64 61 74 61 20 62 79 20 79 6f 75 72 20 6f 77 6e 20 65 66 66 6f 72 74 73 20 6d 61 79 20 72 65 73 75 6c 74 20 69 6e 20 64 61 74 61 20 6c 6f 73 73 } //1 Attempting to recover data by your own efforts may result in data loss
		$a_01_3 = {73 74 6f 70 20 4d 53 53 51 4c 53 45 52 56 45 52 20 2f 66 20 2f 6d } //1 stop MSSQLSERVER /f /m
		$a_01_4 = {70 61 73 73 77 6f 72 64 2d 70 72 6f 74 65 63 74 65 64 20 64 6f 63 75 6d 65 6e 74 73 20 66 72 6f 6d 20 61 20 62 61 6e 6b } //1 password-protected documents from a bank
		$a_03_5 = {68 74 74 70 3a 2f 2f 75 6e 64 67 72 64 90 02 80 2e 6f 6e 69 6f 6e 2f 90 00 } //1
		$a_01_6 = {21 00 21 00 72 00 65 00 61 00 64 00 6d 00 65 00 21 00 21 00 21 00 2e 00 74 00 78 00 74 00 } //1 !!readme!!!.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}