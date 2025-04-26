
rule Ransom_Win32_EregorCrypt_G_MSR{
	meta:
		description = "Ransom:Win32/EregorCrypt.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {49 46 56 43 56 62 41 45 72 76 54 65 42 52 67 55 4e 31 76 51 48 4e 70 35 46 56 74 63 31 57 56 69 } //2 IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi
		$a_01_1 = {4c 6f 30 43 30 33 69 63 45 52 6a 6f 30 4a } //2 Lo0C03icERjo0J
		$a_01_2 = {68 33 6b 70 4a 30 51 45 41 43 35 4f 4a 43 } //2 h3kpJ0QEAC5OJC
		$a_01_3 = {36 75 4c 4e 45 75 35 41 4a 6e 43 69 32 46 45 55 42 33 35 45 55 6d 37 41 66 4d 63 } //2 6uLNEu5AJnCi2FEUB35EUm7AfMc
		$a_01_4 = {4b 6f 6a 69 68 75 44 4a 55 46 44 48 47 75 66 68 64 6a 6e 62 67 44 66 67 75 64 66 68 64 66 67 33 } //1 KojihuDJUFDHGufhdjnbgDfgudfhdfg3
		$a_01_5 = {70 74 4c 66 75 45 53 62 67 4a 6b 41 6d 52 35 63 57 32 75 4a 56 76 } //2 ptLfuESbgJkAmR5cW2uJVv
		$a_01_6 = {72 42 69 51 56 74 4d 6a 4c 36 61 30 71 37 62 53 4a 33 34 4c 74 47 6d 75 } //2 rBiQVtMjL6a0q7bSJ34LtGmu
		$a_01_7 = {68 31 33 63 45 65 4d 35 32 6d 67 } //2 h13cEeM52mg
		$a_01_8 = {45 42 55 61 37 65 67 42 56 4a 31 73 66 6e 70 70 56 68 6e 41 63 46 51 54 62 35 4b 6f 76 33 54 43 46 36 30 48 41 56 6e 74 77 } //2 EBUa7egBVJ1sfnppVhnAcFQTb5Kov3TCF60HAVntw
		$a_01_9 = {69 44 38 73 38 53 4a 44 68 48 46 4a 44 6b 64 6b 66 4f 46 69 67 38 67 38 68 44 6a 53 6b 44 6c 41 } //1 iD8s8SJDhHFJDkdkfOFig8g8hDjSkDlA
		$a_01_10 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //2 expand 32-byte kexpand 16-byte k
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*2) >=11
 
}