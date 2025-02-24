
rule Trojan_AndroidOS_Godfather_L{
	meta:
		description = "Trojan:AndroidOS/Godfather.L,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 48 4a 76 64 47 56 6a 64 44 49 77 4d 6a 42 66 63 33 52 79 } //2 cHJvdGVjdDIwMjBfc3Ry
		$a_01_1 = {59 32 39 74 4c 6d 4e 79 64 58 70 70 5a 58 4a 76 4c 6d 4a 31 62 57 46 79 5a 57 55 3d } //2 Y29tLmNydXppZXJvLmJ1bWFyZWU=
		$a_01_2 = {64 6d 35 6a 63 6d 56 7a 5a 58 51 3d } //2 dm5jcmVzZXQ=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}