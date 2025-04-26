
rule Trojan_Win32_Guloader_AC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 74 61 66 66 65 72 65 74 2e 6d 65 6e } //2 stafferet.men
		$a_81_1 = {70 72 65 70 6f 73 69 6e 67 2e 66 6f 72 } //2 preposing.for
		$a_81_2 = {72 65 66 6f 72 6d 69 73 6d 65 6e 2e 6a 70 67 } //2 reformismen.jpg
		$a_81_3 = {67 64 6e 69 6e 67 73 6f 70 62 65 76 61 72 69 6e 67 65 72 6e 65 2e 69 6e 69 } //2 gdningsopbevaringerne.ini
		$a_81_4 = {62 6f 6c 74 72 6f 70 65 2e 76 61 6e } //2 boltrope.van
		$a_81_5 = {6d 65 6c 6f 64 69 65 72 6e 65 5c 73 76 65 6a 73 68 75 6e 64 65 6e 65 } //2 melodierne\svejshundene
		$a_81_6 = {43 6f 6e 63 6c 75 64 65 6e 74 5c 64 6b 6e 65 72 6e 65 73 } //2 Concludent\dknernes
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2) >=14
 
}
rule Trojan_Win32_Guloader_AC_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a8 cb a1 72 d1 cb a1 72 86 93 a3 72 f9 09 a3 72 01 cc a1 72 0c cc a1 72 31 68 a4 72 29 19 a2 72 62 72 a4 72 88 be a0 72 ba 02 a3 72 41 09 a3 72 } //1
		$a_01_1 = {20 e2 36 4b b8 42 4d 4b 00 00 10 75 d5 a3 02 42 2c f5 8d 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}