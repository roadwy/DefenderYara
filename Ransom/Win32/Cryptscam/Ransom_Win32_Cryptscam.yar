
rule Ransom_Win32_Cryptscam{
	meta:
		description = "Ransom:Win32/Cryptscam,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 69 32 } //2 your files have been encryptedi2
		$a_01_1 = {73 65 6e 64 20 31 20 42 54 43 20 74 6f 20 31 46 31 74 41 61 7a 35 78 31 48 55 58 72 43 4e 4c 62 74 4d 44 71 63 77 36 6f 35 47 4e 37 78 58 37 69 } //2 send 1 BTC to 1F1tAaz5x1HUXrCNLbtMDqcw6o5GN7xX7i
		$a_01_2 = {54 68 65 20 74 69 6d 65 20 69 73 20 6f 76 65 72 } //2 The time is over
		$a_01_3 = {4d 5a 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 21 2e 2e 2e 2e 2e 2e 2e } //2 MZ.......................................................!.......
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}