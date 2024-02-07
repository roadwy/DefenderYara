
rule Trojan_AndroidOS_FakeChat_B{
	meta:
		description = "Trojan:AndroidOS/FakeChat.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 64 61 70 75 72 72 65 } //02 00  adapurre
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 69 6e 61 70 74 75 72 73 74 2e 74 6f 70 2f } //02 00  https://inapturst.top/
		$a_00_2 = {68 75 6c 6b 72 6d 61 6b 65 72 } //02 00  hulkrmaker
		$a_00_3 = {53 41 70 32 32 6d 31 31 } //00 00  SAp22m11
	condition:
		any of ($a_*)
 
}