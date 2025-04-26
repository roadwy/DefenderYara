
rule Ransom_Win32_Inc_MA_MTB{
	meta:
		description = "Ransom:Win32/Inc.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 09 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 49 00 4e 00 43 00 2d 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //10 :\INC-README.txt
		$a_01_1 = {7e 7e 7e 7e 20 49 4e 43 20 52 61 6e 73 6f 6d 20 7e 7e 7e 7e } //10 ~~~~ INC Ransom ~~~~
		$a_03_2 = {68 74 74 70 3a 2f 2f 69 6e 63 70 61 79 [0-50] 2e 6f 6e 69 6f 6e } //10
		$a_01_3 = {49 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 2c 20 77 65 20 77 69 6c 6c 20 61 74 74 61 63 6b 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 61 67 61 69 6e 20 69 6e 20 74 68 65 20 66 75 74 75 72 65 } //1 If you do not pay the ransom, we will attack your company again in the future
		$a_01_4 = {44 6f 6e 27 74 20 67 6f 20 74 6f 20 72 65 63 6f 76 65 72 79 20 63 6f 6d 70 61 6e 69 65 73 } //1 Don't go to recovery companies
		$a_01_5 = {54 68 65 20 70 6f 6c 69 63 65 20 61 6e 64 20 46 42 49 20 77 6f 6e 27 74 20 70 72 6f 74 65 63 74 20 79 6f 75 20 66 72 6f 6d 20 72 65 70 65 61 74 65 64 20 61 74 74 61 63 6b 73 } //1 The police and FBI won't protect you from repeated attacks
		$a_01_6 = {50 61 79 69 6e 67 20 74 68 65 20 72 61 6e 73 6f 6d 20 74 6f 20 75 73 20 69 73 20 6d 75 63 68 20 63 68 65 61 70 65 72 20 61 6e 64 20 6d 6f 72 65 20 70 72 6f 66 69 74 61 62 6c 65 20 74 68 61 6e 20 70 61 79 69 6e 67 20 66 69 6e 65 73 20 61 6e 64 20 6c 65 67 61 6c 20 66 65 65 73 } //1 Paying the ransom to us is much cheaper and more profitable than paying fines and legal fees
		$a_01_7 = {57 61 72 6e 69 6e 67 21 20 44 6f 6e 27 74 20 64 65 6c 65 74 65 20 6f 72 20 6d 6f 64 69 66 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2c 20 69 74 20 77 69 6c 6c 20 6c 65 61 64 20 74 6f 20 70 72 6f 62 6c 65 6d 73 20 77 69 74 68 20 64 65 63 72 79 70 74 69 6f 6e 20 6f 66 20 66 69 6c 65 73 } //1 Warning! Don't delete or modify encrypted files, it will lead to problems with decryption of files
		$a_01_8 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data is stolen and encrypted
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=33
 
}