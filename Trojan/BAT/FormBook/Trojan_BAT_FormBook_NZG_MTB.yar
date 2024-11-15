
rule Trojan_BAT_FormBook_NZG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 06 93 0b 06 18 58 93 07 61 0b } //2
		$a_01_1 = {11 0c 11 07 58 11 09 59 93 61 11 0b } //2
		$a_81_2 = {34 38 33 38 32 32 36 63 2d 31 31 62 37 2d 34 36 62 65 2d 39 36 37 37 2d 38 31 62 62 63 39 36 38 30 63 66 64 } //1 4838226c-11b7-46be-9677-81bbc9680cfd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_NZG_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 32 61 61 37 32 39 65 2d 36 35 37 34 2d 34 62 64 66 2d 61 37 61 36 2d 65 30 64 62 63 38 30 38 35 32 36 62 } //3 e2aa729e-6574-4bdf-a7a6-e0dbc808526b
		$a_01_1 = {00 03 4b 0a 03 04 4b 54 04 06 54 } //1
		$a_01_2 = {91 11 07 11 10 95 61 } //1
		$a_81_3 = {73 65 6e 64 42 75 74 74 6f 6e } //1 sendButton
		$a_81_4 = {50 41 53 53 57 4f 52 44 } //1 PASSWORD
	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}