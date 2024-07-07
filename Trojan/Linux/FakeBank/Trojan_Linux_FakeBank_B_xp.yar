
rule Trojan_Linux_FakeBank_B_xp{
	meta:
		description = "Trojan:Linux/FakeBank.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5f 73 74 72 69 6e 67 49 50 4e 4f 42 61 6e 6b } //1 _stringIPNOBank
		$a_00_1 = {5f 73 74 72 69 6e 67 49 50 42 61 6e 6b } //1 _stringIPBank
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 10 2e 69 65 67 6f 2e 6e 65 74 2f 61 70 70 48 6f 6d 65 2f 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}