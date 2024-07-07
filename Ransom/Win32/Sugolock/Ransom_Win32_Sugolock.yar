
rule Ransom_Win32_Sugolock{
	meta:
		description = "Ransom:Win32/Sugolock,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 6c 6f 63 6b 65 64 21 } //2 All your files locked!
		$a_01_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 65 6d 61 69 6c 3a 20 35 62 74 63 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //2 Your personal email: 5btc@protonmail.com
		$a_01_2 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 73 6f 6d 65 20 62 69 74 63 6f 69 6e 73 20 74 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 21 } //2 You have to pay some bitcoins to unlock your files!
		$a_81_3 = {44 45 43 52 59 50 54 2e 68 74 6d 6c } //2 DECRYPT.html
		$a_01_4 = {35 62 74 63 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //2 5btc@protonmail.com
		$a_01_5 = {44 6f 6e 27 74 20 74 72 79 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 21 } //2 Don't try decrypt your files!
		$a_01_6 = {49 66 20 79 6f 75 20 74 72 79 20 74 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 6d 61 79 20 6c 6f 73 65 20 61 63 63 65 73 73 20 74 6f 20 74 68 65 6d 21 } //2 If you try to unlock your files, you may lose access to them!
		$a_01_7 = {4e 6f 20 6f 6e 65 20 63 61 6e 20 67 75 61 72 61 6e 74 65 65 20 79 6f 75 20 61 20 31 30 30 25 20 75 6e 6c 6f 63 6b 20 65 78 63 65 70 74 20 75 73 21 } //2 No one can guarantee you a 100% unlock except us!
		$a_03_8 = {54 68 65 4a 75 73 74 47 75 73 90 02 18 5c 47 55 53 63 72 79 70 74 6f 6c 6f 63 6b 65 72 20 2d 20 75 70 64 61 74 65 5c 52 65 6c 65 61 73 65 5c 6c 6f 63 6b 65 72 2e 70 64 62 90 00 } //30
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_03_8  & 1)*30) >=38
 
}