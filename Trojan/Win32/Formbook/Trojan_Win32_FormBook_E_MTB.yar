
rule Trojan_Win32_FormBook_E_MTB{
	meta:
		description = "Trojan:Win32/FormBook.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {64 61 72 6b 69 63 6b 40 6d 61 69 6c 2e 72 75 } //3 darkick@mail.ru
		$a_81_1 = {5b 44 61 72 6b 54 65 61 6d 5d } //3 [DarkTeam]
		$a_81_2 = {44 61 72 6b 69 63 6b 20 43 6f 6d 6d 61 6e 64 65 72 20 76 30 2e 39 35 } //3 Darkick Commander v0.95
		$a_81_3 = {53 4e 4c 53 4f 53 50 55 52 4c 47 4c 50 54 56 50 4c 4f 56 } //3 SNLSOSPURLGLPTVPLOV
		$a_81_4 = {57 65 62 53 6e 6f 77 } //3 WebSnow
		$a_81_5 = {57 65 62 46 6c 6f 72 61 6c 57 68 69 74 65 } //3 WebFloralWhite
		$a_81_6 = {57 65 62 42 6c 61 63 6b } //3 WebBlack
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_FormBook_E_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.E!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 92 ab 00 00 05 25 7f 00 00 48 f7 d3 81 e2 14 0c 01 00 f7 d1 58 b9 14 c4 00 00 4a 42 48 f7 d1 05 a2 66 00 00 41 25 8b 0a 01 00 3d b9 0a 00 00 74 06 ba 67 43 00 00 59 4b 5b 81 f1 81 f0 00 00 81 f1 b8 52 00 00 81 c1 a1 f6 00 00 c2 1b 1d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}