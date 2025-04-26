
rule Ransom_Win64_SuchCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/SuchCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR,22 00 22 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 47 65 72 6a 78 4e 45 66 79 34 67 48 42 59 70 42 36 34 76 32 2f 6a 6f 4e 54 61 6c 47 4a 65 39 55 38 59 67 36 64 66 50 79 32 2f 75 6d 72 49 44 53 79 6a 53 34 6c 4d 65 69 43 36 78 57 6a 56 2f 4b 73 78 4c 6d 41 37 76 39 4e 6f 55 6d 56 42 74 72 2d 34 45 22 } //10 Go build ID: "GerjxNEfy4gHBYpB64v2/joNTalGJe9U8Yg6dfPy2/umrIDSyjS4lMeiC6xWjV/KsxLmA7v9NoUmVBtr-4E"
		$a_01_1 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //10 at  fp= is  lr: of  on  pc= sp: sp=
		$a_01_2 = {73 69 7a 65 20 3d 20 2e 6d 77 61 68 61 68 61 68 32 34 34 31 34 30 36 32 35 } //10 size = .mwahahah244140625
		$a_01_3 = {64 65 63 72 79 70 74 } //1 decrypt
		$a_01_4 = {65 6e 63 72 79 70 74 } //1 encrypt
		$a_01_5 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //1 createtoolhelp32snapshot
		$a_01_6 = {73 75 63 68 2d 63 72 79 70 74 2f 6d 61 69 6e 2e 67 6f } //1 such-crypt/main.go
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=34
 
}