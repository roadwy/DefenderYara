
rule Trojan_AndroidOS_FakeChat_B{
	meta:
		description = "Trojan:AndroidOS/FakeChat.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 64 61 70 75 72 72 65 } //2 adapurre
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 69 6e 61 70 74 75 72 73 74 2e 74 6f 70 2f } //2 https://inapturst.top/
		$a_00_2 = {68 75 6c 6b 72 6d 61 6b 65 72 } //2 hulkrmaker
		$a_00_3 = {53 41 70 32 32 6d 31 31 } //2 SAp22m11
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}