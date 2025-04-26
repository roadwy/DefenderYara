
rule Trojan_Linux_FakeBank_GV_xp{
	meta:
		description = "Trojan:Linux/FakeBank.GV!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5f 73 74 72 69 6e 67 49 50 31 } //1 _stringIP1
		$a_00_1 = {5f 73 74 72 69 6e 67 49 50 42 61 6e 6b } //1 _stringIPBank
		$a_02_2 = {68 74 74 70 3a 2f 2f [0-10] 2e 69 65 67 6f 2e 6e 65 74 2f 61 70 70 48 6f 6d 65 2f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}