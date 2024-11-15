
rule Trojan_AndroidOS_BlankBot_B_MTB{
	meta:
		description = "Trojan:AndroidOS/BlankBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 61 73 64 61 } //1 RecorderServiceasda
		$a_01_1 = {74 65 6e 62 69 73 2f 6c 69 62 72 61 72 79 2f 76 69 65 77 73 2f 43 6f 6d 70 61 63 74 43 72 65 64 69 74 43 61 72 64 49 6e 70 75 74 } //1 tenbis/library/views/CompactCreditCardInput
		$a_01_2 = {49 6e 61 74 62 6f 78 } //1 Inatbox
		$a_01_3 = {64 65 6c 65 74 65 53 6d 73 } //1 deleteSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}