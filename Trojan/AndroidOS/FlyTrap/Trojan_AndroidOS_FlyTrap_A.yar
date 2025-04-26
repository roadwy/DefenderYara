
rule Trojan_AndroidOS_FlyTrap_A{
	meta:
		description = "Trojan:AndroidOS/FlyTrap.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {59 6e 73 75 70 65 72 } //2 Ynsuper
		$a_01_1 = {43 6f 6f 6b 69 65 4d 61 6e 61 67 65 72 2e 67 65 74 49 6e 73 74 61 6e 63 e2 80 a6 2e 55 52 4c 5f 47 45 54 5f 43 4f 4f 4b 49 45 5f 46 41 43 45 42 4f 4f 4b } //2
		$a_00_2 = {2f 4c 6f 67 69 6e 41 63 74 69 76 69 74 79 24 73 65 74 55 70 44 65 66 61 75 6c 74 57 65 62 43 6c 69 65 6e 74 24 31 } //2 /LoginActivity$setUpDefaultWebClient$1
		$a_00_3 = {3b 20 70 61 73 73 77 6f 72 64 3a 20 } //2 ; password: 
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}