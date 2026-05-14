
rule Trojan_Win32_Zusy_PGAQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {28 3f 3a 5e 34 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d 24 29 } //(?:^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)  2
		$a_80_1 = {28 3f 3a 5e 58 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 33 7d 24 29 } //(?:^X[1-9A-HJ-NP-Za-km-z]{33}$)  2
		$a_80_2 = {28 28 62 69 74 63 6f 69 6e 63 61 73 68 3a 29 3f 28 71 7c 70 29 5b 61 2d 7a 30 2d 39 5d 7b 34 31 7d 29 } //((bitcoincash:)?(q|p)[a-z0-9]{41})  2
		$a_80_3 = {28 55 51 7c 45 51 29 5b 61 2d 7a 41 2d 5a 30 2d 39 5f 2d 5d 7b 34 36 7d 24 } //(UQ|EQ)[a-zA-Z0-9_-]{46}$  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}