
rule Trojan_Win32_Guloader_DEC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 00 61 00 6e 00 64 00 73 00 74 00 6f 00 72 00 6d 00 65 00 6e 00 65 00 73 00 } //1 Sandstormenes
		$a_01_1 = {4d 00 61 00 73 00 6b 00 69 00 6e 00 75 00 64 00 76 00 61 00 6c 00 67 00 73 00 33 00 } //1 Maskinudvalgs3
		$a_01_2 = {4b 00 76 00 61 00 72 00 74 00 65 00 72 00 72 00 61 00 70 00 70 00 6f 00 72 00 74 00 65 00 72 00 6e 00 65 00 73 00 38 00 } //1 Kvarterrapporternes8
		$a_01_3 = {76 00 65 00 6c 00 79 00 6e 00 64 00 65 00 72 00 6e 00 65 00 73 00 } //1 velyndernes
		$a_01_4 = {48 00 61 00 6c 00 76 00 66 00 6a 00 65 00 72 00 64 00 73 00 61 00 61 00 72 00 73 00 66 00 64 00 73 00 65 00 6c 00 73 00 64 00 61 00 67 00 65 00 6e 00 73 00 } //2 Halvfjerdsaarsfdselsdagens
		$a_01_5 = {44 00 6e 00 78 00 50 00 50 00 49 00 33 00 5a 00 75 00 78 00 6d 00 59 00 34 00 6c 00 7a 00 4a 00 53 00 30 00 41 00 56 00 54 00 6e 00 72 00 46 00 54 00 59 00 39 00 6d 00 4a 00 32 00 75 00 51 00 32 00 32 00 39 00 } //2 DnxPPI3ZuxmY4lzJS0AVTnrFTY9mJ2uQ229
		$a_01_6 = {45 00 6b 00 73 00 70 00 6f 00 73 00 69 00 74 00 69 00 6f 00 6e 00 73 00 64 00 65 00 6c 00 65 00 6e 00 65 00 33 00 } //2 Ekspositionsdelene3
		$a_01_7 = {62 00 6a 00 72 00 67 00 6e 00 69 00 6e 00 67 00 73 00 66 00 61 00 72 00 74 00 6a 00 65 00 74 00 } //2 bjrgningsfartjet
		$a_01_8 = {4f 00 6c 00 69 00 65 00 74 00 61 00 6e 00 6b 00 62 00 65 00 6b 00 65 00 6e 00 64 00 74 00 67 00 72 00 65 00 6c 00 73 00 65 00 32 00 } //2 Olietankbekendtgrelse2
		$a_01_9 = {46 00 6f 00 6c 00 6b 00 65 00 74 00 69 00 6e 00 67 00 73 00 6d 00 65 00 64 00 6c 00 65 00 6d 00 6d 00 65 00 72 00 6e 00 65 00 73 00 36 00 } //2 Folketingsmedlemmernes6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=2
 
}