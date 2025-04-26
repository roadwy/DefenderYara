
rule Trojan_BAT_Folnamer_A{
	meta:
		description = "Trojan:BAT/Folnamer.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 6d 61 57 78 6c 4c 6d 56 34 5a 53 49 3d } //1 Rm9sZGVyTmFtZVxmaWxlLmV4ZSI=
		$a_01_1 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 74 5a 57 78 30 4c 6d 4a 68 64 41 3d 3d } //1 Rm9sZGVyTmFtZVxtZWx0LmJhdA==
		$a_01_2 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 74 59 58 52 68 4d 69 35 69 59 58 51 3d } //1 Rm9sZGVyTmFtZVxtYXRhMi5iYXQ=
		$a_01_3 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 4e 61 57 4e 79 62 33 4e 76 5a 6e 51 74 51 57 4e 6a 5a 58 4e 7a 4c 54 49 77 4d 54 4d 75 59 6d 46 30 } //1 Rm9sZGVyTmFtZVxNaWNyb3NvZnQtQWNjZXNzLTIwMTMuYmF0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}