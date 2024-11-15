
rule Trojan_AndroidOS_BlankBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/BlankBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {21 28 35 81 0f 00 46 08 02 01 6e 20 a1 25 80 00 13 08 2e 00 6e 20 99 25 80 00 d8 01 01 01 28 f1 } //1
		$a_01_1 = {52 65 63 6f 72 64 69 6e 67 20 53 63 72 65 65 6e 21 } //1 Recording Screen!
		$a_01_2 = {6b 65 79 43 6f 64 65 73 } //1 keyCodes
		$a_01_3 = {74 65 6e 62 69 73 2f 6c 69 62 72 61 72 79 2f 76 69 65 77 73 2f 43 6f 6d 70 61 63 74 43 72 65 64 69 74 43 61 72 64 49 6e 70 75 74 } //1 tenbis/library/views/CompactCreditCardInput
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}