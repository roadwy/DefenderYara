
rule Trojan_BAT_Ekidoa_A_bit{
	meta:
		description = "Trojan:BAT/Ekidoa.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 69 6e 00 68 68 68 68 00 55 6e 5a 69 70 } //1
		$a_01_1 = {64 00 61 00 6f 00 4c 00 } //1 daoL
		$a_01_2 = {74 00 6e 00 69 00 6f 00 70 00 79 00 72 00 74 00 6e 00 45 00 } //1 tniopyrtnE
		$a_01_3 = {65 00 6b 00 6f 00 76 00 6e 00 49 00 } //1 ekovnI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}